#include "logtopf.h"

int           sort_col = 9;
int           sort_dir = -1;
int           scroll_offset = 0;
int           show_help = 0;
static int    g_n = 0;
static time_t g_now;
static int    col_widths[NUM_COLS];

static struct {
    uint16_t port;
    uint8_t  proto;
    char     name[16];
} svc_cache[64];
static int svc_cache_count = 0;

static const char *lookup_service(uint16_t port, uint8_t proto) {
    for (int i = 0; i < svc_cache_count; i++)
        if (svc_cache[i].port == port && svc_cache[i].proto == proto)
            return svc_cache[i].name;
    if (svc_cache_count < 64) {
        const char     *pn = (proto == IPPROTO_UDP) ? "udp" : "tcp";
        struct servent *se = getservbyport(htons(port), pn);
        if (se) {
            svc_cache[svc_cache_count].port = port;
            svc_cache[svc_cache_count].proto = proto;
            strncpy(svc_cache[svc_cache_count].name, se->s_name, 15);
            svc_cache[svc_cache_count].name[15] = '\0';
            svc_cache_count++;
            return svc_cache[svc_cache_count - 1].name;
        }
    }
    return NULL;
}

static const char *proto_name(uint8_t p) {
    switch (p) {
    case IPPROTO_TCP:
        return "tcp";
    case IPPROTO_UDP:
        return "udp";
    case IPPROTO_ICMP:
        return "icmp";
    case IPPROTO_ICMPV6:
        return "icmp6";
    default: {
        static char buf[8];
        snprintf(buf, sizeof(buf), "%u", p);
        return buf;
    }
    }
}

static void human_bytes(uint64_t b, char *out, size_t n) {
    static const char *iec_units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    static const char *si_units[]  = { "B", "KB",  "MB",  "GB",  "TB" };
    double             d = base_1024 ? 1024.0 : 1000.0;
    const char       **u = base_1024 ? iec_units : si_units;
    double             v = (double)b;
    int                i = 0;
    while (v >= d && i < 4) {
        v /= d;
        i++;
    }
    if (i)
        snprintf(out, n, "%.1f%s", v, u[i]);
    else
        snprintf(out, n, "%llu%s", (unsigned long long)b, u[0]);
}

static void human_rate(double bps, char *out, size_t n) {
    static const char *iec_units[] = { "B", "KiB", "MiB", "GiB" };
    static const char *si_units[]  = { "B", "KB",  "MB",  "GB" };
    double             d = base_1024 ? 1024.0 : 1000.0;
    const char       **u = base_1024 ? iec_units : si_units;
    if (bps >= d * d * d)
        snprintf(out, n, "%.2f%s", bps / (d * d * d), u[3]);
    else if (bps >= d * d)
        snprintf(out, n, "%.2f%s", bps / (d * d), u[2]);
    else if (bps >= d)
        snprintf(out, n, "%.1f%s", bps / d, u[1]);
    else
        snprintf(out, n, "%.0f%s", bps, u[0]);
}

static const char *trunc_str(const char *s, int maxw) {
    if (maxw <= 0)
        return "";
    if ((int)strlen(s) <= maxw)
        return s;
    static char bufs[2][128];
    static int  idx = 0;
    int         cur = idx;
    idx = (idx + 1) % 2;
    int keep = maxw - 3;
    if (keep < 1)
        keep = 1;
    snprintf(bufs[cur], sizeof(bufs[cur]), "%.*s...", keep, s);
    return bufs[cur];
}

static int cmp_flow_generic(const void *a, const void *b) {
    const struct flow_display *fa = (const struct flow_display *)a;
    const struct flow_display *fb = (const struct flow_display *)b;
    int                        res = 0;

    switch (sort_col) {
    case 0:
        res = fa->direction - fb->direction;
        break;
    case 1:
        res = strcmp(fa->src_host, fb->src_host);
        break;
    case 2:
        res = strcmp(fa->dst_host, fb->dst_host);
        break;
    case 3:
        res = (fa->proto < fb->proto) ? -1 : (fa->proto > fb->proto);
        break;
    case 4:
        res = strcmp(fa->f->service_name, fb->f->service_name);
        break;
    case 5:
        res = strcmp(fa->rule_display, fb->rule_display);
        break;
    case 6:
        res = strcmp(fa->ifname, fb->ifname);
        break;
    case 7: {
        uint64_t pa = fa->packets;
        uint64_t pb = fb->packets;
        res = (pa < pb) ? -1 : (pa > pb);
        break;
    }
    case 8: {
        uint64_t ba = fa->bytes;
        uint64_t bb = fb->bytes;
        res = (ba < bb) ? -1 : (ba > bb);
        break;
    }
    case 9: {
        double ra = fa->rate_val;
        double rb = fb->rate_val;
        res = (ra < rb) ? -1 : (ra > rb);
        break;
    }
    case 10:
        res = (fa->last_age < fb->last_age) ? -1 : (fa->last_age > fb->last_age);
        break;
    case 11:
        res = (fa->action < fb->action) ? -1 : (fa->action > fb->action);
        break;
    }
    if (res == 0 && sort_col != 10) {
        long aa = fa->last_age;
        long ab = fb->last_age;
        res = (aa > ab) ? -1 : (aa < ab);
    }
    if (res == 0)
        res = (fa->f < fb->f) ? -1 : (fa->f > fb->f);
    return sort_dir * res;
}

static struct flow_display display[MAX_ENTRIES];
static int                 layout_cols = -1;

/* The worker adds bytes, then l3, then l4, then stores last_us. Reading in the
   reverse order means raw always covers the headers read, so it can't wrap. */
static struct counters read_counters(struct flow *f) {
    struct counters c;
    c.us = atomic_load(&f->last_us);
    c.l4 = atomic_load(&f->l4_hdr_bytes);
    c.l3 = atomic_load(&f->l3_hdr_bytes);
    c.raw = atomic_load(&f->bytes);
    return c;
}

static uint64_t effective(const struct counters *c) {
    uint64_t hdr = (count_l3_hdr ? 0 : c->l3) + (count_l4_hdr ? 0 : c->l4);
    return c->raw > hdr ? c->raw - hdr : 0;
}

static void rate_reset(struct flow *f) {
    memset(&f->rate_ref, 0, sizeof(f->rate_ref));
    f->rate_cached = 0.0;
}

/*
 * Rate = bytes between a reference point and the latest packet, over the time
 * between them, both taken from the worker's packet timestamps rather than the
 * draw clock, so BPF delivering packets in bursts doesn't make the rate jump.
 * The reference moves forward once it is RATE_WINDOW seconds old; a flow idle
 * for over a second reads 0. Keeping raw and header counts apart means the
 * L3/L4 toggles apply to both ends and never cause a spike.
 */
static uint64_t rate_update_flow(struct flow *f, uint64_t now_us) {
    struct counters  c = read_counters(f);
    struct counters *ref = &f->rate_ref;
    if (ref->us == 0 || (now_us > c.us && now_us - c.us > 1000000ULL)) {
        *ref = c;
        f->rate_cached = 0.0;
    } else if (c.us > ref->us) {
        uint64_t cur = effective(&c), prev = effective(ref);
        uint64_t dt = c.us - ref->us;
        f->rate_cached = cur > prev ? (double)(cur - prev) * 1e6 / (double)dt : 0.0;
        if (dt >= (uint64_t)RATE_WINDOW * 1000000ULL)
            *ref = c;
    }
    return effective(&c);
}

/* UI-owned per-flow state is reset whenever the worker reassigns the slot. */
static void ui_flow_reset(struct flow *f) {
    inet_ntop(f->src.ss_family, get_addr_ptr(&f->src), f->src_ip, sizeof(f->src_ip));
    inet_ntop(f->dst.ss_family, get_addr_ptr(&f->dst), f->dst_ip, sizeof(f->dst_ip));
    f->src_internal = is_internal_addr(&f->src);
    f->dst_internal = is_internal_addr(&f->dst);
    f->src_name[0] = '\0';
    f->dst_name[0] = '\0';
    f->service_name[0] = '\0';
    rate_reset(f);
}

static void update_display_cache(void) {
    int n = 0;
    pthread_mutex_lock(&flow_lock);
    for (int i = 0; i < MAX_ENTRIES; i++) {
        struct flow *f = &flows[i];
        if (!f->used)
            continue;
        uint32_t gen = atomic_load(&f->generation);
        if (gen != f->ui_gen) {
            f->ui_gen = gen;
            ui_flow_reset(f);
        }
        struct flow_display *d = &display[n++];
        d->f = f;
        d->proto = f->proto;
        d->action = f->action;
        d->direction = f->direction;
        d->port = f->port;
        memcpy(d->ifname, f->ifname, sizeof(d->ifname));
        memcpy(d->rule_display, f->rule_display, sizeof(d->rule_display));
        d->src = f->src;
        d->dst = f->dst;
    }
    pthread_mutex_unlock(&flow_lock);
    g_n = n;

    time_t          now = time(NULL);
    g_now = now;

    if (resolve_hostnames) {
        int any_unresolved = 0;
        pthread_rwlock_rdlock(&hostlock);
        for (unsigned i = 0; i < (unsigned)g_n; i++) {
            struct flow *f = display[i].f;
            if (f->src_name[0] == '\0' &&
                !get_host_locked_internal(&display[i].src, f->src_name, sizeof(f->src_name), 0))
                any_unresolved = 1;
            if (f->dst_name[0] == '\0' &&
                !get_host_locked_internal(&display[i].dst, f->dst_name, sizeof(f->dst_name), 0))
                any_unresolved = 1;
        }
        pthread_rwlock_unlock(&hostlock);

        if (any_unresolved) {
            pthread_rwlock_wrlock(&hostlock);
            for (unsigned i = 0; i < (unsigned)g_n; i++) {
                struct flow *f = display[i].f;
                if (f->src_name[0] == '\0')
                    get_host_locked_internal(&display[i].src, f->src_name, sizeof(f->src_name), 1);
                if (f->dst_name[0] == '\0')
                    get_host_locked_internal(&display[i].dst, f->dst_name, sizeof(f->dst_name), 1);
            }
            pthread_rwlock_unlock(&hostlock);
        }
    }

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_us = (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;

    for (unsigned i = 0; i < (unsigned)g_n; i++) {
        struct flow *f = display[i].f;

        if (!resolve_ports || f->service_name[0] == '\0') {
            uint16_t port = display[i].port;
            if (port) {
                if (resolve_ports) {
                    const char *sn = lookup_service(port, display[i].proto);
                    if (sn)
                        strncpy(f->service_name, sn, sizeof(f->service_name) - 1);
                    else
                        snprintf(f->service_name, sizeof(f->service_name), "%u", port);
                } else {
                    snprintf(f->service_name, sizeof(f->service_name), "%u", port);
                }
            } else {
                f->service_name[0] = '-';
                f->service_name[1] = '\0';
            }
        }

        display[i].src_host = (resolve_hostnames && f->src_name[0]) ? f->src_name : f->src_ip;
        display[i].dst_host = (resolve_hostnames && f->dst_name[0]) ? f->dst_name : f->dst_ip;
        display[i].packets = atomic_load(&f->packets);
        uint64_t last_us = atomic_load(&f->last_us);
        display[i].last_age = (long)((now_us > last_us ? now_us - last_us : 0) / 1000000ULL);

        /* Rate */
        {
            display[i].bytes = rate_update_flow(f, now_us);
            display[i].rate_val = f->rate_cached;
        }
    }
    qsort(display, g_n, sizeof(display[0]), cmp_flow_generic);
}

/* Row output clipped at the right edge; ncurses would wrap the rest onto the
   next line, where it stays when that line is the last row or blank. */
static int put_x, put_cols;

static void put_start(int row) {
    move(row, 0);
    put_x = 0;
    put_cols = COLS;
}

static void put(const char *s, int n) {
    int room = put_cols - put_x;
    if (n > room)
        n = room;
    if (n <= 0)
        return;
    addnstr(s, n);
    put_x += n;
}

static void render_line(int screen_row, struct flow_display *d) {
    struct flow *f = d->f;
    int          idir = d->direction;
    put_start(screen_row);
    clrtoeol();

    char  bh[16], rh[16];
    human_bytes(d->bytes, bh, sizeof(bh));
    human_rate(d->rate_val, rh, sizeof(rh));

    const char *src = trunc_str(d->src_host, col_widths[1]);
    const char *dst = trunc_str(d->dst_host, col_widths[2]);

    static const char *dirs[] = { "In/Out", "In", "Out" };
    const char        *dir = (idir < 3) ? dirs[idir] : "???";
    char               age_buf[16];
    snprintf(age_buf, sizeof(age_buf), "%lds", d->last_age);
    const char *proto = proto_name(d->proto);
    /* pf's PF_PASS .. PF_MATCH, at most 7 chars to fit the column */
    static const char *acts[] = { "pass", "block", "scrub", "noscrub", "nat", "nonat", "binat",
                                  "nobinat", "rdr", "nordr", "synprxy", "defer", "match" };
    const char        *act = d->action < sizeof(acts) / sizeof(acts[0]) ? acts[d->action] : "?";

    char seg[128];
    int  off;

    int dw = col_widths[0];
    if (show_color_mode) {
        if (idir == 1)
            attron(COLOR_PAIR(2));
        else if (idir == 2)
            attron(COLOR_PAIR(3));
    }
    char dcell[64];
    snprintf(dcell, sizeof(dcell), "%-*s", dw, dir);
    put(dcell, dw - 1);
    if (show_color_mode) {
        attroff(COLOR_PAIR(2));
        attroff(COLOR_PAIR(3));
    }
    put(&dcell[dw - 1], 1);
    put(" ", 1);

    if (f->src_internal && show_int_color)
        attron(COLOR_PAIR(4));
    off = snprintf(seg, sizeof(seg), "%-*.*s ", col_widths[1], col_widths[1], src);
    put(seg, off);
    if (f->src_internal && show_int_color)
        attroff(COLOR_PAIR(4));

    if (f->dst_internal && show_int_color)
        attron(COLOR_PAIR(4));
    off = snprintf(seg, sizeof(seg), "%-*.*s ", col_widths[2], col_widths[2], dst);
    put(seg, off);
    if (f->dst_internal && show_int_color)
        attroff(COLOR_PAIR(4));

    char tail[384];
    off = snprintf(tail, sizeof(tail),
                   "%-*.*s %-*.*s %-*s %-*s %-*llu %-*s",
                   col_widths[3], col_widths[3], proto,
                   col_widths[4], col_widths[4], f->service_name,
                   col_widths[5], d->rule_display,
                   col_widths[6], d->ifname,
                   col_widths[7], (unsigned long long)d->packets,
                   col_widths[8], bh);
    put(tail, off);

    double rv = d->rate_val;
    double k  = base_1024 ? 1024.0 : 1000.0;
    if (show_color_mode && rv > 0) {
        int rp;
        if (rv < k)
            rp = 7;
        else if (rv < 10 * k)
            rp = 8;
        else if (rv < 100 * k)
            rp = 9;
        else if (rv < k * k)
            rp = 10;
        else
            rp = 11;
        attron(COLOR_PAIR(rp));
    }
    off = snprintf(seg, sizeof(seg), " %-*s", col_widths[9], rh);
    put(seg, off);
    if (show_color_mode && rv > 0) {
        attroff(COLOR_PAIR(7));
        attroff(COLOR_PAIR(8));
        attroff(COLOR_PAIR(9));
        attroff(COLOR_PAIR(10));
        attroff(COLOR_PAIR(11));
    }

    off = snprintf(tail, sizeof(tail), " %-*s %-*.*s",
                   col_widths[10], age_buf,
                   col_widths[11], col_widths[11], act);
    put(tail, off);
}

static void draw_status_row(int cols, int refresh_stats, int start, int shown) {
    static struct pcap_stat ps;
    static char             tbuf[64];
    if (refresh_stats) {
        if (pcap_stats(pd, &ps) < 0)
            memset(&ps, 0, sizeof(ps));
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&g_now));
    }

    uint64_t fill   = (uint64_t)(atomic_load(&ring_atomics.head) - atomic_load(&ring_atomics.tail));
    uint64_t adrops = atomic_load(&ring_atomics.drops);

    char left[256], right[128];
    char scroll_bar[16];
    {
        int max = g_n > shown ? g_n - shown : 1;
        int pos = start * 8 / max;
        if (pos < 0)
            pos = 0;
        if (pos > 7)
            pos = 7;
        for (int i = 0; i < 8; i++)
            scroll_bar[i + 1] = i < pos ? '=' : i == pos ? '#' : ' ';
        scroll_bar[0]  = '[';
        scroll_bar[9]  = ']';
        scroll_bar[10] = '\0';
    }
    attron(COLOR_PAIR(5));
    snprintf(left, sizeof(left), "logtopf flows: %d %s  %s",
             g_n, scroll_bar, tbuf);
    snprintf(right, sizeof(right), "RX:%llu BUF:%llu%% DROPS:KRN:%llu APP:%llu",
             (unsigned long long)ps.ps_recv,
             (unsigned long long)(fill * 100 / RING_SIZE),
             (unsigned long long)ps.ps_drop, (unsigned long long)adrops);
    int rpos = cols - (int)strlen(right);
    if (rpos < 0)
        rpos = 0;
    if ((int)strlen(left) > rpos)
        left[rpos] = '\0';
    move(0, 0);
    clrtoeol();
    addnstr(left, (int)strlen(left));
    mvaddnstr(0, rpos, right, cols - rpos);
    attroff(COLOR_PAIR(5));
}

static void draw_config_row(int cols) {
    move(1, 0);
    clrtoeol();
    attron(COLOR_PAIR(6));
    mvprintw(1, 0, "RES:%s  COL:%s  INT:%s  UNIT:%d  SRVC:%s  HDR:L3%c L4%c",
             resolve_hostnames ? "ON" : "OFF",
             show_color_mode ? "ON" : "OFF",
             show_int_color ? "ON" : "OFF",
             base_1024 ? 1024 : 1000,
             resolve_ports ? "ON" : "OFF",
             count_l3_hdr ? '+' : '-',
             count_l4_hdr ? '+' : '-');
    /* the full key list if it fits next to the settings, else a pointer to it */
    int         used = getcurx(stdscr);
    const char *help_text = "(q:quit x:clear c:col r:res i:int u:unit p:srvc 3/4:hdr s:sort <>:col ?:keys)";
    if (used + 2 + (int)strlen(help_text) > cols)
        help_text = "(?:keys q:quit)";
    int hpos = cols - (int)strlen(help_text);
    if (hpos >= used + 2)
        mvprintw(1, hpos, "%s", help_text);
    attroff(COLOR_PAIR(6));
}

static void draw_column_header(void) {
    static const char *col_names[] = { "DIR", "SRC", "DST", "PROTO", "PORT", "RULE", "IFACE", "PKTS", "BYTES", "RATE", "AGE", "ACTION" };
    char               name[16], cell[128];
    attron(COLOR_PAIR(1));
    put_start(2);
    for (unsigned i = 0; i < NUM_COLS; i++) {
        int sorted = i == (unsigned)sort_col;
        snprintf(name, sizeof(name), "%s%s", col_names[i], sorted ? (sort_dir == -1 ? "^" : "v") : "");
        int n = snprintf(cell, sizeof(cell), "%-*.*s%s", col_widths[i], col_widths[i], name,
                         i < NUM_COLS - 1 ? " " : "");
        if (sorted)
            attron(A_BOLD);
        put(cell, n);
        if (sorted)
            attroff(A_BOLD);
    }
    attroff(COLOR_PAIR(1));
    mvwhline(stdscr, 3, 0, ACS_HLINE, COLS);
}

static int help_drawn;

static void draw_help(int rows, int cols) {
    static const char *lines[] = {
        "Up/Down   scroll           Left/Right  sort column",
        "s         reverse sort     x           clear the table",
        "r         hostnames        p           port names",
        "c         colour           i           local addresses",
        "u         KiB or KB        3 / 4       count L3 / L4 headers",
        "Ctrl-L    repaint          q           quit",
        "",
        "                 any key closes this",
    };
    int n = (int)(sizeof(lines) / sizeof(lines[0])), w = 0;
    for (int i = 0; i < n; i++)
        if ((int)strlen(lines[i]) > w)
            w = (int)strlen(lines[i]);
    int bw = w + 4, bh = n + 2;
    int y0 = (rows - bh) / 2, x0 = (cols - bw) / 2;
    if (y0 < 0)
        y0 = 0;
    if (x0 < 0)
        x0 = 0;
    attron(COLOR_PAIR(5));
    for (int r = 0; r < bh && y0 + r < rows; r++) {
        move(y0 + r, x0);
        for (int c = 0; c < bw && x0 + c < cols; c++)
            addch(' ');
    }
    for (int i = 0; i < n; i++)
        mvaddnstr(y0 + 1 + i, x0 + 2, lines[i], cols - x0 - 2);
    mvaddstr(y0, x0 + 2, " keys ");
    attroff(COLOR_PAIR(5));
}

static void render_flow_region(int start, int shown, int region_rows) {
    static int last_shown = 0;
    for (int i = 0; i < shown; i++)
        render_line(4 + i, &display[start + i]);
    for (int i = shown; i < last_shown && i < region_rows; i++) {
        move(4 + i, 0);
        clrtoeol();
    }
    last_shown = shown;
}

void draw(int update_data) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    if (update_data)
        update_display_cache();
    if (cols != layout_cols) {
        layout_cols = cols;
        int widths[NUM_COLS] = { 6, 15, 15, 5, 12, 8, 8, 8, 9, 8, 6, 7 };
        int fixed = 0;
        for (unsigned i = 0; i < NUM_COLS; i++)
            fixed += widths[i];
        int leftover = cols - (fixed + 11);
        for (int i = 0; i < NUM_COLS; i++)
            col_widths[i] = widths[i];
        /* spare width goes to the address columns, up to what a long hostname
           or IPv6 address needs; past that, rows simply end before the edge */
        if (leftover > 0) {
            int grow = leftover / 2 < 30 ? leftover / 2 : 30;
            col_widths[1] += grow;
            col_widths[2] += grow;
        }
    }

    int region_rows = rows - 4;
    int shown       = region_rows;
    if (shown > g_n)
        shown = g_n;
    int start = scroll_offset;
    if (start + shown > g_n)
        start = g_n - shown;
    if (start < 0)
        start = 0;
    scroll_offset = start;

    /* the overlay covers rows nothing else redraws: start from a blank
       screen when it closes (ncurses still only sends what changed) */
    if (help_drawn && !show_help)
        erase();

    int refresh_stats = (update_data != 0);
    draw_status_row(cols, refresh_stats, start, shown);
    draw_config_row(cols);
    draw_column_header();
    render_flow_region(start, shown, region_rows);
    if (show_help)
        draw_help(rows, cols);
    help_drawn = show_help;

    doupdate();
}
