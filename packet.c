#include "logtopf.h"

struct ring_entry    ring[RING_SIZE];

struct ring_atomics ring_atomics __attribute__((aligned(64))) = {0};

sem_t                ring_sem;

/*
 * FreeBSD's struct pfloghdr (net/if_pflog.h), as far as we read it. The kernel
 * header is 69 bytes on FreeBSD 14+ and padded to 72 on the wire; `length`
 * tells us where the IP packet starts, so newer trailing fields don't matter.
 */
struct pfloghdr {
    uint8_t  length;
    uint8_t  af;
    uint8_t  action;
    uint8_t  reason;
    char     ifname[16];
    char     ruleset[16];
    uint32_t rulenr;
    uint32_t subrulenr;
    uint32_t uid;
    int32_t  pid;
    uint32_t rule_uid;
    int32_t  rule_pid;
    uint8_t  dir;
} __attribute__((packed));

#define PFLOG_MIN_LEN ((int)sizeof(struct pfloghdr))

static void set_addr4(struct sockaddr_storage *ss, struct in_addr a) {
    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    memset(sin, 0, sizeof(*sin));
#ifdef SIN6_LEN
    sin->sin_len = sizeof(*sin);
#endif
    sin->sin_family = AF_INET;
    sin->sin_addr = a;
}

static void set_addr6(struct sockaddr_storage *ss, const void *a) { /* a may be unaligned */
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
    memset(sin6, 0, sizeof(*sin6));
#ifdef SIN6_LEN
    sin6->sin6_len = sizeof(*sin6);
#endif
    sin6->sin6_family = AF_INET6;
    memcpy(&sin6->sin6_addr, a, sizeof(sin6->sin6_addr));
}

static void parse_packet_meta(const u_char *bytes, int caplen, struct parsed_meta *meta, struct sockaddr_storage *src, struct sockaddr_storage *dst) {
    memset(meta, 0, sizeof(*meta));
    if (caplen < PFLOG_MIN_LEN)
        return;
    const struct pfloghdr *ph = (const struct pfloghdr *)bytes;
    int                    hdrlen = BPF_WORDALIGN(ph->length);
    if (hdrlen < PFLOG_MIN_LEN || caplen < hdrlen)
        return;

    const u_char *pkt = bytes + hdrlen;
    int           len = caplen - hdrlen;
    int           l4_offset;
    int           has_l4 = 1;

    if (ph->af == AF_INET) {
        if (len < (int)sizeof(struct ip))
            return;
        const struct ip *ip = (const struct ip *)pkt;
        int              ihl = ip->ip_hl * 4;
        if (ihl < (int)sizeof(struct ip) || len < ihl)
            return;
        set_addr4(src, ip->ip_src);
        set_addr4(dst, ip->ip_dst);
        meta->proto = ip->ip_p;
        meta->iplen = ntohs(ip->ip_len);
        meta->ip_hdr_len = ihl;
        l4_offset = ihl;
        /* non-first fragments carry no L4 header */
        if (ntohs(ip->ip_off) & IP_OFFMASK)
            has_l4 = 0;
    } else if (ph->af == AF_INET6) {
        if (len < (int)sizeof(struct ip6_hdr))
            return;
        const struct ip6_hdr *ip = (const struct ip6_hdr *)pkt;
        set_addr6(src, (const u_char *)ip + offsetof(struct ip6_hdr, ip6_src));
        set_addr6(dst, (const u_char *)ip + offsetof(struct ip6_hdr, ip6_dst));
        meta->iplen = sizeof(struct ip6_hdr) + ntohs(ip->ip6_plen);
        int nxt = ip->ip6_nxt;
        l4_offset = sizeof(struct ip6_hdr);
        /* walk extension headers so the protocol and ports are the real ones */
        for (int hops = 0; hops < 8; hops++) {
            if (nxt != IPPROTO_HOPOPTS && nxt != IPPROTO_ROUTING && nxt != IPPROTO_DSTOPTS &&
                nxt != IPPROTO_FRAGMENT && nxt != IPPROTO_AH)
                break;
            if (len < l4_offset + 8) {
                has_l4 = 0;
                break;
            }
            const u_char *e = pkt + l4_offset;
            if (nxt == IPPROTO_FRAGMENT && ((e[2] << 8 | e[3]) & 0xfff8))
                has_l4 = 0;
            int elen = nxt == IPPROTO_FRAGMENT ? 8 : nxt == IPPROTO_AH ? (e[1] + 2) * 4 : (e[1] + 1) * 8;
            nxt = e[0];
            l4_offset += elen;
        }
        meta->proto = (uint8_t)nxt;
        meta->ip_hdr_len = l4_offset > 255 ? 255 : (uint8_t)l4_offset;
    } else
        return;

    const u_char *l4 = pkt + l4_offset;
    int           l4len = len - l4_offset;
    if (!has_l4) {
        /* no ports */
    } else if (meta->proto == IPPROTO_TCP && l4len >= (int)sizeof(struct tcphdr)) {
        const struct tcphdr *t = (const struct tcphdr *)l4;
        meta->sport = ntohs(t->th_sport);
        meta->dport = ntohs(t->th_dport);
        meta->l4_hdr_len = t->th_off * 4;
    } else if (meta->proto == IPPROTO_UDP && l4len >= (int)sizeof(struct udphdr)) {
        const struct udphdr *u = (const struct udphdr *)l4;
        meta->sport = ntohs(u->uh_sport);
        meta->dport = ntohs(u->uh_dport);
        meta->l4_hdr_len = sizeof(struct udphdr);
    }

    meta->action = ph->action;
    meta->dir = ph->dir;
    meta->rule_id = ntohl(ph->rulenr);
    meta->subrule_id = ntohl(ph->subrulenr);
    meta->valid = 1;
}

static void process_packet(struct ring_entry *re, uint64_t now_us) {
    struct parsed_meta *meta = &re->meta;
    if (!meta->valid)
        return;

    /* The service port is the lower of the two: right for client->server packets
       and for replies alike, whichever direction pf logged them in. */
    uint16_t key_port = meta->sport < meta->dport ? meta->sport : meta->dport;
    struct flow *f = get_or_create_flow(re, key_port);

    atomic_fetch_add(&f->packets, 1);
    atomic_fetch_add(&f->bytes, meta->iplen);
    atomic_fetch_add(&f->l3_hdr_bytes, meta->ip_hdr_len);
    atomic_fetch_add(&f->l4_hdr_bytes, meta->l4_hdr_len);
    atomic_store(&f->last_us, now_us);
}

void *worker_thread(void *arg) {
    (void)arg;
    while (running) {
        uint64_t head = atomic_load_explicit(&ring_atomics.head, memory_order_acquire);
        uint64_t tail = atomic_load_explicit(&ring_atomics.tail, memory_order_relaxed);
        if (head == tail) {
            apply_pending_clear();
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 50000000;
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000L;
            }
            sem_timedwait(&ring_sem, &ts);
            continue;
        }

        apply_pending_clear();
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t now_us = (uint64_t)now.tv_sec * 1000000ULL + now.tv_nsec / 1000;
        int      count = 0;
        while (tail < head) {
            process_packet(&ring[tail % RING_SIZE], now_us);
            tail++;
            if (++count >= 64) {
                atomic_store_explicit(&ring_atomics.tail, tail, memory_order_release);
                count = 0;
            }
        }
        atomic_store_explicit(&ring_atomics.tail, tail, memory_order_release);
    }
    return NULL;
}

static void pkt_handler(u_char *ud, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)ud;

    uint64_t head = atomic_load(&ring_atomics.head);
    uint64_t tail = atomic_load_explicit(&ring_atomics.tail, memory_order_acquire);

    /* The kernel hands packets over a buffer at a time, far faster than the
       worker aggregates them. When the ring is full, wait for the worker
       rather than drop: meanwhile the kernel keeps buffering. Only drop if the
       worker makes no progress for a second or two. Sleeping, not yielding, so
       the worker gets the CPU even on one core under our real-time priority. */
    if (head - tail >= RING_SIZE) {
        struct timespec start, now;
        clock_gettime(CLOCK_MONOTONIC, &start);
        sem_post(&ring_sem);
        while (head - tail >= RING_SIZE) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - start.tv_sec >= 2) {
                atomic_fetch_add(&ring_atomics.drops, 1);
                return;
            }
            usleep(100);
            tail = atomic_load_explicit(&ring_atomics.tail, memory_order_acquire);
        }
    }

    struct ring_entry *re = &ring[head % RING_SIZE];

    int len = h->caplen < MAX_PKT_SIZE ? h->caplen : MAX_PKT_SIZE;

    // Pre-parse everything here
    parse_packet_meta(bytes, len, &re->meta, &re->src, &re->dst);

    if (len >= PFLOG_MIN_LEN) {
        struct pfloghdr *ph = (struct pfloghdr *)bytes;
        memcpy(re->ruleset_raw, ph->ruleset, 16);
        memcpy(re->ifname_raw, ph->ifname, 16);
    }

    atomic_store_explicit(&ring_atomics.head, head + 1, memory_order_release);
    if (head == atomic_load_explicit(&ring_atomics.tail, memory_order_acquire)) {
        sem_post(&ring_sem);
    }
}

void *cap_thread(void *arg) {
    (void)arg;
    pcap_loop(pd, -1, pkt_handler, NULL);
    return NULL;
}
