/*
 * pktgen: write crafted Ethernet frames into a FreeBSD interface through BPF.
 *
 * Writing on epair0b delivers the frame to epair0a's input path, so pf sees a
 * real inbound packet on epair0a and logs it to pflog0 if a rule says so.
 *
 *   pktgen -i epair0b -d <epair0a mac> [options]
 *     -n N      flows (default 1)
 *     -c N      packets per flow (default 1)
 *     -l N      L4 payload bytes (default 0)
 *     -r N      packets per second, 0 = as fast as possible (default 0)
 *     -p P      tcp | udp | icmp (default tcp)
 *     -P N      server port (default 80)
 *     -m M      what varies per flow: src | dst | sport (default src)
 *     -6        IPv6 instead of IPv4
 *     -H        IPv6: insert a hop-by-hop extension header
 *     -F        IPv4: send each packet as two fragments
 *     -R        flip direction: server port is the source port (reply traffic)
 *     -o N      offset added to the flow index for source addresses (default 0)
 *
 * Flow i uses src 198.18.0.0+i (fd00:98::i), dst 10.99.0.1 (fd00:99::1),
 * client port 40000+i. Prints one line per flow: src dst sport dport packets ip_bytes.
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/bpf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint8_t frame[2048];

static uint32_t sum16(const void *p, size_t n, uint32_t s) {
    const uint8_t *b = p;
    for (; n > 1; n -= 2, b += 2)
        s += (uint32_t)(b[0] << 8 | b[1]);
    if (n)
        s += (uint32_t)(b[0] << 8);
    return s;
}

static uint16_t fold(uint32_t s) {
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return htons((uint16_t)~s);
}

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static int parse_mac(const char *s, uint8_t *m) {
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        m[i] = (uint8_t)v[i];
    return 0;
}

/* Build L4 header + payload at p; returns length. Checksum filled by caller via pseudo-header sum. */
static int build_l4(uint8_t *p, int proto, uint16_t sport, uint16_t dport, int plen) {
    int h;
    if (proto == IPPROTO_TCP) {
        h = 20;
        memset(p, 0, h);
        put16(p, sport);
        put16(p + 2, dport);
        p[12] = 5 << 4;
        p[13] = 0x18; /* PSH|ACK */
        put16(p + 14, 65535);
    } else if (proto == IPPROTO_UDP) {
        h = 8;
        put16(p, sport);
        put16(p + 2, dport);
        put16(p + 4, (uint16_t)(h + plen));
        put16(p + 6, 0);
    } else { /* icmp / icmp6 echo request */
        h = 8;
        memset(p, 0, h);
        p[0] = proto == IPPROTO_ICMP ? 8 : 128;
        put16(p + 4, sport);
    }
    memset(p + h, 'x', plen);
    return h + plen;
}

static int csum_off(int proto) {
    return proto == IPPROTO_TCP ? 16 : proto == IPPROTO_UDP ? 6 : 2;
}

int main(int argc, char **argv) {
    const char *ifn = NULL;
    uint8_t     dmac[6] = { 0 }, smac[6] = { 0x02, 0, 0, 0, 0x99, 0x02 };
    int         off0 = 0, nflows = 1, per = 1, plen = 0, pps = 0, v6 = 0, hbh = 0, frag = 0, reply = 0;
    int         proto = IPPROTO_TCP, sport_mode = 0, dst_mode = 0;
    uint16_t    port = 80;
    int         c;

    while ((c = getopt(argc, argv, "i:d:n:c:l:r:p:P:m:o:6HFR")) != -1) {
        switch (c) {
        case 'i': ifn = optarg; break;
        case 'd': if (parse_mac(optarg, dmac)) errx(1, "bad mac"); break;
        case 'n': nflows = atoi(optarg); break;
        case 'c': per = atoi(optarg); break;
        case 'l': plen = atoi(optarg); break;
        case 'r': pps = atoi(optarg); break;
        case 'P': port = (uint16_t)atoi(optarg); break;
        case '6': v6 = 1; break;
        case 'H': hbh = 1; break;
        case 'F': frag = 1; break;
        case 'R': reply = 1; break;
        case 'o': off0 = atoi(optarg); break;
        case 'p':
            proto = !strcmp(optarg, "udp") ? IPPROTO_UDP : !strcmp(optarg, "icmp") ? -1 : IPPROTO_TCP;
            break;
        case 'm':
            sport_mode = !strcmp(optarg, "sport");
            dst_mode = !strcmp(optarg, "dst");
            break;
        default: errx(1, "see source for usage");
        }
    }
    if (!ifn)
        errx(1, "-i required");
    if (proto == -1)
        proto = v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP;
    if (plen > 1400)
        plen = 1400;

    int fd = open("/dev/bpf", O_RDWR);
    if (fd < 0)
        err(1, "/dev/bpf");
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifn, sizeof(ifr.ifr_name));
    if (ioctl(fd, BIOCSETIF, &ifr) < 0)
        err(1, "BIOCSETIF %s", ifn);
    u_int one = 1;
    ioctl(fd, BIOCSHDRCMPLT, &one);

    uint64_t       *ipbytes = calloc(nflows, sizeof(uint64_t));
    uint64_t       *pkts = calloc(nflows, sizeof(uint64_t));
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t sent = 0;

    for (int k = 0; k < per; k++) {
        for (int i = 0; i < nflows; i++) {
            uint16_t cport = (uint16_t)(40000 + (sport_mode ? i : 0) + (dst_mode || sport_mode ? 0 : i % 20000));
            uint16_t sp = reply ? port : cport, dp = reply ? cport : port;
            uint8_t *eth = frame, *ip = frame + 14;
            memcpy(eth, dmac, 6);
            memcpy(eth + 6, smac, 6);
            int iplen;

            if (!v6) {
                eth[12] = 0x08, eth[13] = 0x00;
                uint32_t src = 0xc6120000u + (uint32_t)off0 + (uint32_t)(sport_mode || dst_mode ? 0 : i);
                uint32_t dst = 0x0a630001u + (uint32_t)(dst_mode ? i + 16 : 0);
                uint8_t *l4 = ip + 20;
                int      l4len = build_l4(l4, proto, sp, dp, plen);
                uint32_t s = 0;
                if (proto != IPPROTO_ICMP) {
                    uint8_t ph[12];
                    uint32_t sn = htonl(src), dn = htonl(dst);
                    memcpy(ph, &sn, 4), memcpy(ph + 4, &dn, 4);
                    ph[8] = 0, ph[9] = (uint8_t)proto, put16(ph + 10, (uint16_t)l4len);
                    s = sum16(ph, 12, 0);
                }
                uint16_t ck = fold(sum16(l4, l4len, s));
                memcpy(l4 + csum_off(proto), &ck, 2);

                int nfr = frag ? 2 : 1;
                int first = frag ? ((l4len / 2) & ~7) : l4len;
                if (frag && first < 8)
                    first = 8;
                for (int f = 0; f < nfr; f++) {
                    int off = f ? first : 0, len = f ? l4len - first : first;
                    uint8_t *h = ip;
                    if (f)
                        memmove(ip + 20, l4 + off, len);
                    memset(h, 0, 20);
                    h[0] = 0x45;
                    put16(h + 2, (uint16_t)(20 + len));
                    put16(h + 4, (uint16_t)(i + k));
                    put16(h + 6, (uint16_t)((frag && !f ? 0x2000 : 0) | (off / 8)));
                    h[8] = 64, h[9] = (uint8_t)proto;
                    uint32_t sn = htonl(src), dn = htonl(dst);
                    memcpy(h + 12, &sn, 4), memcpy(h + 16, &dn, 4);
                    uint16_t hc = fold(sum16(h, 20, 0));
                    memcpy(h + 10, &hc, 2);
                    iplen = 20 + len;
                    if (write(fd, frame, 14 + iplen) < 0)
                        err(1, "write");
                    ipbytes[i] += iplen;
                    pkts[i]++;
                    sent++;
                }
            } else {
                eth[12] = 0x86, eth[13] = 0xdd;
                uint8_t src[16] = { 0xfd, 0, 0, 0x98 }, dst[16] = { 0xfd, 0, 0, 0x99 };
                uint32_t sv = (uint32_t)off0 + (uint32_t)(sport_mode || dst_mode ? 1 : i + 1);
                src[12] = sv >> 24, src[13] = sv >> 16, src[14] = sv >> 8, src[15] = sv;
                dst[15] = (uint8_t)(dst_mode ? 0x10 + i : 1);
                dst[14] = (uint8_t)(dst_mode ? (0x10 + i) >> 8 : 0);
                int      ext = hbh ? 8 : 0;
                uint8_t *l4 = ip + 40 + ext;
                int      l4len = build_l4(l4, proto, sp, dp, plen);
                uint8_t  ph[40];
                memcpy(ph, src, 16), memcpy(ph + 16, dst, 16);
                ph[32] = ph[33] = 0, put16(ph + 34, (uint16_t)l4len);
                ph[36] = ph[37] = ph[38] = 0, ph[39] = (uint8_t)proto;
                uint16_t ck = fold(sum16(l4, l4len, sum16(ph, 40, 0)));
                memcpy(l4 + csum_off(proto), &ck, 2);
                memset(ip, 0, 40);
                ip[0] = 0x60;
                put16(ip + 4, (uint16_t)(ext + l4len));
                ip[6] = hbh ? 0 : (uint8_t)proto;
                ip[7] = 64;
                memcpy(ip + 8, src, 16), memcpy(ip + 24, dst, 16);
                if (hbh) {
                    uint8_t *e = ip + 40;
                    memset(e, 0, 8);
                    e[0] = (uint8_t)proto;
                    e[2] = 1, e[3] = 4; /* PadN, 4 bytes */
                }
                iplen = 40 + ext + l4len;
                if (write(fd, frame, 14 + iplen) < 0)
                    err(1, "write");
                ipbytes[i] += iplen;
                pkts[i]++;
                sent++;
            }

            if (pps > 0) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                double el = (now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9;
                double due = (double)sent / pps;
                if (due > el)
                    usleep((useconds_t)((due - el) * 1e6));
            }
        }
    }

    for (int i = 0; i < nflows; i++) {
        char     s[64], d[64];
        uint16_t cport = (uint16_t)(40000 + (sport_mode ? i : 0) + (dst_mode || sport_mode ? 0 : i % 20000));
        if (!v6) {
            struct in_addr a = { htonl(0xc6120000u + (uint32_t)off0 + (uint32_t)(sport_mode || dst_mode ? 0 : i)) };
            struct in_addr b = { htonl(0x0a630001u + (uint32_t)(dst_mode ? i + 16 : 0)) };
            inet_ntop(AF_INET, &a, s, sizeof(s));
            inet_ntop(AF_INET, &b, d, sizeof(d));
        } else {
            snprintf(s, sizeof(s), "fd00:98::%x", off0 + (sport_mode || dst_mode ? 1 : i + 1));
            snprintf(d, sizeof(d), "fd00:99::%x", dst_mode ? 0x10 + i : 1);
        }
        printf("%s %s %u %u %llu %llu\n", s, d, reply ? port : cport, reply ? cport : port,
               (unsigned long long)pkts[i], (unsigned long long)ipbytes[i]);
    }
    return 0;
}
