#ifndef LOGTOPF_H
#define LOGTOPF_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <pcap.h>
#include <pcap/bpf.h>
#include <ncurses.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <semaphore.h>
#include "net_utils.h"

#ifndef DLT_PFLOG
#define DLT_PFLOG 117
#endif

#define MAX_ENTRIES   2048
#define HASH_BUCKETS  4096
#define MAX_HOSTS     4096
#define MAX_HOSTNAME  256
#define RATE_WINDOW   2

#define RING_SIZE    16384
#define MAX_PKT_SIZE 192 /* 72 pflog + 40 IPv6 + extension headers + TCP */
#define DEFAULT_BUF_KIB 4096 /* kernel capture buffer, -B to change */
#define NUM_COLS     12

struct parsed_meta {
    uint8_t  proto;
    uint8_t  action;
    uint8_t  dir;
    uint8_t  ip_hdr_len;
    uint8_t  l4_hdr_len;
    uint8_t  valid;
    uint16_t sport;
    uint16_t dport;
    uint32_t iplen;
    uint32_t rule_id;
    uint32_t subrule_id;
};

struct ring_entry {
    struct parsed_meta      meta;
    char                    ruleset_raw[16];
    char                    ifname_raw[16];
    struct sockaddr_storage src, dst;
};

/* A consistent-enough read of a flow's counters (see read_counters in ui.c). */
struct counters {
    uint64_t raw, l3, l4, us;
};

/*
 * A flow slot. The key, ifname and rule are written by the worker only while
 * holding flow_lock (when the slot is (re)assigned); the UI copies them under
 * the same lock. Counters are atomics updated lock-free on the hot path.
 * Everything below "UI-owned" is touched only by the UI thread, which resets
 * it whenever it sees `generation` change.
 */
struct flow {
    int                     used;
    int                     accessed;
    struct sockaddr_storage src, dst;
    uint8_t                 proto;
    uint8_t                 action;
    uint8_t                 direction;
    char                    ifname[16];
    char                    rule_display[48];
    uint16_t                port; /* service port: min(sport, dport) */
    _Atomic uint32_t        generation;
    _Atomic uint64_t        packets, bytes;
    _Atomic uint64_t        l3_hdr_bytes, l4_hdr_bytes;
    _Atomic uint64_t        last_us;

    /* UI-owned */
    uint32_t        ui_gen;
    struct counters rate_ref;
    double          rate_cached;
    char     src_ip[INET6_ADDRSTRLEN];
    char     dst_ip[INET6_ADDRSTRLEN];
    char     src_name[MAX_HOSTNAME];
    char     dst_name[MAX_HOSTNAME];
    char     service_name[32];
    int      src_internal;
    int      dst_internal;
};

/* One row as the UI sees it: worker-owned fields are copied under flow_lock. */
struct flow_display {
    struct flow *f;
    const char  *src_host;
    const char  *dst_host;
    double       rate_val;
    uint64_t     packets;
    uint64_t     bytes;
    long         last_age;
    uint8_t      proto;
    uint8_t      action;
    uint8_t      direction;
    uint16_t     port;
    char         ifname[16];
    char         rule_display[48];
    struct sockaddr_storage src, dst;
};

extern struct flow           flows[MAX_ENTRIES];
extern pthread_mutex_t       flow_lock;
extern pcap_t               *pd;
extern struct ring_atomics {
    _Atomic uint64_t head;
    char _pad1[56];
    _Atomic uint64_t tail;
    char _pad2[56];
    _Atomic uint64_t drops;
    char _pad3[56];
} ring_atomics;
extern sem_t                 ring_sem;
extern volatile int          running;
extern volatile int          resolve_hostnames;
extern pthread_rwlock_t      hostlock;
extern volatile int          show_color_mode;
extern volatile int          show_int_color;
extern volatile int          base_1024;
extern volatile int          count_l3_hdr;
extern volatile int          count_l4_hdr;
extern volatile int          resolve_ports;
extern volatile sig_atomic_t resize_pending;
extern int                   sort_col;
extern int                   sort_dir;
extern int                   scroll_offset;
extern int                   show_help;

uint32_t     addr_hash(const struct sockaddr_storage *a);
int          addr_eq(const struct sockaddr_storage *a, const struct sockaddr_storage *b);
const void  *get_addr_ptr(const struct sockaddr_storage *addr);
int          find_host_idx(const struct sockaddr_storage *addr);
int          get_host_locked_internal(const struct sockaddr_storage *addr, char *out, size_t outlen, int allow_write);
void        *resolver_thread(void *arg);
struct flow *get_or_create_flow(const struct ring_entry *re, uint16_t key_port);
void         init_flow_table(void);
void         request_clear(void);
void         apply_pending_clear(void);
void        *cap_thread(void *arg);
void        *worker_thread(void *arg);
void         draw(int update_data);

#endif
