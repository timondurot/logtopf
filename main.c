#include "logtopf.h"
#include <sched.h>
#include <sys/ioctl.h>

pcap_t               *pd;
volatile int          running = 1;
volatile int          resolve_hostnames = 1;
volatile int          show_color_mode = 1;
volatile int          show_int_color = 1;
volatile int          base_1024 = 1;
volatile int          count_l3_hdr = 0;
volatile int          count_l4_hdr = 0;
volatile int          resolve_ports = 1;
volatile sig_atomic_t resize_pending = 0;

static void handle_sigwinch(int sig) {
    (void)sig;
    resize_pending = 1;
}

static void init_color_pairs(void) {
    if (has_colors() || getenv("FORCE_COLOR")) {
        start_color();
        use_default_colors();
        if (COLORS >= 256) {
            init_pair(1, COLOR_WHITE, 236);
            init_pair(2, -1, 167);
            init_pair(3, -1, 72);
            init_pair(4, 106, -1);
            init_pair(5, 250, 236);
            init_pair(6, 244, -1);
            /* rate gradient, dark enough to read on light terminals too */
            init_pair(7, 136, -1);
            init_pair(8, 172, -1);
            init_pair(9, 166, -1);
            init_pair(10, 202, -1);
            init_pair(11, 196, -1);
        } else {
            init_pair(1, COLOR_WHITE, COLOR_BLACK);
            init_pair(2, -1, COLOR_RED);
            init_pair(3, -1, COLOR_GREEN);
            init_pair(4, COLOR_GREEN, -1);
            init_pair(5, COLOR_WHITE, COLOR_BLACK);
            init_pair(6, COLOR_WHITE, -1);
            init_pair(7, COLOR_YELLOW, -1);
            init_pair(8, COLOR_YELLOW, -1);
            init_pair(9, COLOR_YELLOW, -1);
            init_pair(10, COLOR_YELLOW, -1);
            init_pair(11, COLOR_YELLOW, -1);
        }
    }
}

static long ms_since(const struct timespec *t) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - t->tv_sec) * 1000 + (now.tv_nsec - t->tv_nsec) / 1000000;
}

/* Has the last frame left the tty? On a slow serial line it may still be
   queued, and drawing another one would only add to the backlog. */
static int output_drained(void) {
    int n = 0;
    return ioctl(STDOUT_FILENO, TIOCOUTQ, &n) != 0 || n == 0;
}

static void handle_resize(void) {
    resize_pending = 0;
    endwin();
    refresh();
    keypad(stdscr, TRUE);
    init_color_pairs();
}

static void on_sig(int s) {
    (void)s;
    running = 0;
}

static int handle_input(int ch) {
    if (show_help) { /* any key closes the key overlay */
        show_help = 0;
        return 2;
    }
    switch (ch) {
    case '\f': /* Ctrl-L: repaint everything, e.g. after line noise */
        clearok(curscr, TRUE);
        return 2;
    case KEY_LEFT:
        sort_col = (sort_col > 0) ? sort_col - 1 : NUM_COLS - 1;
        scroll_offset = 0;
        return 2;
    case KEY_RIGHT:
        sort_col = (sort_col < NUM_COLS - 1) ? sort_col + 1 : 0;
        scroll_offset = 0;
        return 2;
    case KEY_UP:
        if (scroll_offset > 0)
            scroll_offset--;
        return 1;
    case KEY_DOWN:
        scroll_offset++;
        return 1;
    default: {
        int lc = (ch >= 'A' && ch <= 'Z') ? ch + ('a' - 'A') : ch;
        switch (lc) {
        case 'q':
            running = 0;
            return 0;
        case 'c':
            show_color_mode = !show_color_mode;
            return 2;
        case 'x':
            request_clear();
            return 2;
        case 'r':
            resolve_hostnames = !resolve_hostnames;
            return 2;
        case 'i':
            show_int_color = !show_int_color;
            return 2;
        case 'u':
            base_1024 = !base_1024;
            return 2;
        case '3':
            count_l3_hdr = !count_l3_hdr;
            return 2;
        case '4':
            count_l4_hdr = !count_l4_hdr;
            return 2;
        case 'p':
            resolve_ports = !resolve_ports;
            for (int i = 0; i < MAX_ENTRIES; i++)
                flows[i].service_name[0] = '\0';
            return 2;
        case 's':
            sort_dir = -sort_dir;
            scroll_offset = 0;
            return 2;
        case '?':
        case 'h':
            show_help = 1;
            return 2;
        }
    }
    }
    return 0;
}

static void usage(FILE *f) {
    fprintf(f, "usage: logtopf [-h] [-B buffer_size] [interface]\n\n"
               "Live view of the packets pf logs. The interface defaults to pflog0.\n"
               "Press ? while it runs to see the keys.\n");
}

int main(int argc, char **argv) {
    int  opt;
    long buf_kib = 0;
    while ((opt = getopt(argc, argv, "B:h")) != -1) {
        if (opt == 'B') {
            char *end;
            buf_kib = strtol(optarg, &end, 10);
            if (*end == '\0' && buf_kib > 0 && buf_kib <= 1024 * 1024)
                continue;
            fprintf(stderr, "logtopf: -B wants a size in KiB, 1 to 1048576\n");
            return 1;
        }
        usage(opt == 'h' ? stdout : stderr);
        return opt == 'h' ? 0 : 1;
    }
    if (argc - optind > 1) {
        usage(stderr);
        return 1;
    }
    const char *iface = optind < argc ? argv[optind] : "pflog0";
    char        errbuf[PCAP_ERRBUF_SIZE];

    pd = pcap_create(iface, errbuf);
    if (!pd) {
        fprintf(stderr, "pcap_create: %s\n", errbuf);
        return 1;
    }
    pcap_set_snaplen(pd, MAX_PKT_SIZE);
    pcap_set_buffer_size(pd, (int)((buf_kib ? buf_kib : DEFAULT_BUF_KIB) * 1024));
    pcap_set_timeout(pd, 500);

    if (pcap_activate(pd) < 0) {
        fprintf(stderr, "pcap_activate: %s\n", pcap_geterr(pd));
        return 1;
    }

    if (pcap_datalink(pd) != DLT_PFLOG) {
        fprintf(stderr, "error: %s is not a pflog interface (datalink %d)\n", iface, pcap_datalink(pd));
        return 1;
    }

    if (buf_kib && pcap_bufsize(pd) < buf_kib * 1024)
        fprintf(stderr, "warning: asked for a %ld KiB capture buffer, got %d KiB (net.bpf.maxbufsize)\n",
                buf_kib, pcap_bufsize(pd) / 1024);

    struct sigaction sa = { 0 };
    sa.sa_handler = on_sig;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = handle_sigwinch;
    sigaction(SIGWINCH, &sa, NULL);

    pthread_t cap_tid, res_tid, wrk_tid;

    init_flow_table();
    init_internal_nets();
    sem_init(&ring_sem, 0, 0);

    if (pthread_create(&cap_tid, NULL, cap_thread, NULL) != 0) {
        fprintf(stderr, "failed to create capture thread\n");
        pcap_close(pd);
        return 1;
    }

    /* Best effort real-time priority for the capture thread, so busy user
       processes can't keep it from emptying the kernel buffer. Not pinned to a
       core: under load the kernel's own packet threads can fill any one core,
       and a pinned thread then never runs. */
    struct sched_param param;
    param.sched_priority = 10;
    pthread_setschedparam(cap_tid, SCHED_RR, &param);

    if (pthread_create(&res_tid, NULL, resolver_thread, NULL) != 0 ||
        pthread_create(&wrk_tid, NULL, worker_thread, NULL) != 0) {
        fprintf(stderr, "failed to create threads\n");
        running = 0;
        pthread_cancel(cap_tid);
        pthread_join(cap_tid, NULL);
        pcap_close(pd);
        return 1;
    }

    initscr();

    noecho();
    cbreak();
    curs_set(0);
    keypad(stdscr, TRUE);
    typeahead(-1);
    /* let ncurses scroll with the terminal's scroll region: on a 9600 baud line
       this roughly halves the lag after a held arrow key is released */
    idlok(stdscr, TRUE);
    init_color_pairs();

    struct timespec next_draw;
    clock_gettime(CLOCK_MONOTONIC, &next_draw);
    /* align to 1-second boundary */
    next_draw.tv_nsec = 0;
    next_draw.tv_sec += 1;

    struct timespec last_scroll_draw = { 0, 0 };
    int             scroll_pending = 0;

    while (running) {
        if (resize_pending) {
            handle_resize();
            draw(2);
            clock_gettime(CLOCK_MONOTONIC, &next_draw);
            next_draw.tv_nsec = 0;
            next_draw.tv_sec += 1;
            continue;
        }
        timeout(scroll_pending ? 10 : 100);
        int ch = getch();
        if (ch != ERR) {
            int rv = handle_input(ch);
            if (rv == 2) {
                draw(2);
                scroll_pending = 0;
                continue;
            }
            if (rv == 1)
                scroll_pending = 1;
        }
        /* Scroll frames: at most 20 a second, and only once the previous one
           has gone out, so on a slow line a held key skips ahead instead of
           queueing frames that keep scrolling after it is released. */
        if (scroll_pending && ms_since(&last_scroll_draw) >= 50 && output_drained()) {
            clock_gettime(CLOCK_MONOTONIC, &last_scroll_draw);
            draw(0);
            scroll_pending = 0;
        }
        struct timespec mono_now;
        clock_gettime(CLOCK_MONOTONIC, &mono_now);
        if (mono_now.tv_sec > next_draw.tv_sec ||
            (mono_now.tv_sec == next_draw.tv_sec && mono_now.tv_nsec >= next_draw.tv_nsec)) {
            draw(1);
            scroll_pending = 0;
            next_draw.tv_sec += 1;
        }
    }

    endwin();
    pcap_breakloop(pd);
    pthread_cancel(cap_tid);
    pthread_join(cap_tid, NULL);
    pthread_cancel(res_tid);
    pthread_join(res_tid, NULL);
    pthread_cancel(wrk_tid);
    pthread_join(wrk_tid, NULL);
    pcap_close(pd);
    cleanup_internal_nets();
    return 0;
}
