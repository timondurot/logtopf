#include "logtopf.h"

struct host_entry {
    int                     used;
    int                     resolved;
    struct sockaddr_storage addr;
    char                    name[NI_MAXHOST];
};

struct host_entry hosts[MAX_HOSTS];
pthread_rwlock_t  hostlock = PTHREAD_RWLOCK_INITIALIZER;
/* hosts[] and the queue are protected by hostlock */
static int        unresolved_q[MAX_HOSTS];
static int        q_head, q_tail, q_count, hosts_used;
struct flow       flows[MAX_ENTRIES];
pthread_mutex_t   flow_lock = PTHREAD_MUTEX_INITIALIZER;
static int        bucket_head[HASH_BUCKETS]; /* worker-only: chains of flow indices */
static int        bucket_next[MAX_ENTRIES];
static int        clock_hand;
static _Atomic int clear_requested;

uint32_t addr_hash(const struct sockaddr_storage *a) {
    if (a->ss_family == AF_INET) {
        uint32_t h = ((struct sockaddr_in *)a)->sin_addr.s_addr;
        h ^= h >> 16;
        h *= 0x9e3779b9;
        h ^= h >> 13;
        return h;
    }
    const uint64_t *p = (const uint64_t *)&((struct sockaddr_in6 *)a)->sin6_addr;
    uint64_t        h64 = p[0] ^ p[1];
    h64 *= 0x9e3779b97f4a7c15ULL;
    return (uint32_t)(h64 ^ (h64 >> 32));
}

static uint32_t flow_key_hash(const struct sockaddr_storage *src, const struct sockaddr_storage *dst, uint8_t proto, uint16_t port, uint8_t action, uint8_t dir) {
    uint32_t h = addr_hash(src) * 0x85ebca6bu;
    h ^= addr_hash(dst) + 0x9e3779b9u + (h << 6) + (h >> 2);
    h ^= ((uint32_t)port << 16 | (uint32_t)proto << 8 | (uint32_t)action << 2 | dir) * 0xc2b2ae35u;
    h ^= h >> 16;
    h *= 0x7feb352du;
    h ^= h >> 15;
    return h;
}

int addr_eq(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family)
        return 0;
    if (a->ss_family == AF_INET)
        return ((struct sockaddr_in *)a)->sin_addr.s_addr == ((struct sockaddr_in *)b)->sin_addr.s_addr;
    const uint64_t *a6 = (const uint64_t *)&((struct sockaddr_in6 *)a)->sin6_addr;
    const uint64_t *b6 = (const uint64_t *)&((struct sockaddr_in6 *)b)->sin6_addr;
    return (a6[0] == b6[0] && a6[1] == b6[1]);
}

const void *get_addr_ptr(const struct sockaddr_storage *addr) {
    return addr->ss_family == AF_INET ? (const void *)&((struct sockaddr_in *)addr)->sin_addr : (const void *)&((struct sockaddr_in6 *)addr)->sin6_addr;
}

/* Worker thread (or startup) only. Generations are kept so the UI notices reuse. */
void init_flow_table(void) {
    pthread_mutex_lock(&flow_lock);
    for (int i = 0; i < MAX_ENTRIES; i++) {
        flows[i].used = 0;
        flows[i].accessed = 0;
    }
    memset(bucket_head, -1, sizeof(bucket_head));
    clock_hand = 0;
    pthread_mutex_unlock(&flow_lock);
}

/* UI thread: ask the worker to clear the table and wait briefly so the next draw is empty. */
void request_clear(void) {
    atomic_store(&clear_requested, 1);
    sem_post(&ring_sem);
    for (int i = 0; i < 100 && atomic_load(&clear_requested); i++)
        usleep(1000);
}

void apply_pending_clear(void) {
    if (atomic_load_explicit(&clear_requested, memory_order_relaxed)) {
        init_flow_table();
        atomic_store(&clear_requested, 0);
    }
}

int find_host_idx(const struct sockaddr_storage *addr) {
    uint32_t h = addr_hash(addr);
    for (unsigned i = 0; i < MAX_HOSTS; i++) {
        int idx = (h + i) & (MAX_HOSTS - 1);
        if (!hosts[idx].used)
            return -1;
        if (addr_eq(&hosts[idx].addr, addr))
            return idx;
    }
    return -1;
}

int get_host_locked_internal(const struct sockaddr_storage *addr, char *out, size_t outlen, int allow_write) {
    if (!resolve_hostnames)
        return 0;
    int idx = find_host_idx(addr);
    if (idx == -1 && allow_write) {
        /* Keep the open-addressed table at most 3/4 full: start over when it fills.
           Flows keep the names they already copied. */
        if (hosts_used >= MAX_HOSTS * 3 / 4) {
            for (int i = 0; i < MAX_HOSTS; i++)
                hosts[i].used = 0;
            q_head = q_tail = q_count = hosts_used = 0;
        }
        uint32_t h = addr_hash(addr);
        for (unsigned i = 0; i < MAX_HOSTS; i++) {
            int tidx = (h + i) & (MAX_HOSTS - 1);
            if (!hosts[tidx].used) {
                idx = tidx;
                hosts[idx].used = 1;
                hosts[idx].resolved = 0;
                hosts[idx].addr = *addr;
                hosts[idx].name[0] = '\0';
                hosts_used++;
                unresolved_q[q_tail] = idx;
                q_tail = (q_tail + 1) % MAX_HOSTS;
                q_count++;
                break;
            }
        }
    }
    if (idx != -1 && hosts[idx].resolved) {
        strncpy(out, hosts[idx].name, outlen - 1);
        out[outlen - 1] = 0;
        return 1;
    }
    return 0;
}

void *resolver_thread(void *arg) {
    (void)arg;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    while (running) {
        pthread_testcancel();
        int                     idx = -1;
        struct sockaddr_storage addr;
        memset(&addr, 0, sizeof(addr));

        pthread_rwlock_wrlock(&hostlock);
        if (q_count > 0) {
            idx = unresolved_q[q_head];
            q_head = (q_head + 1) % MAX_HOSTS;
            q_count--;
            if (hosts[idx].used) {
                addr = hosts[idx].addr;
                hosts[idx].resolved = 1;
            } else {
                idx = -1;
            }
            pthread_rwlock_unlock(&hostlock);

            if (idx < 0) {
                usleep(300000);
                continue;
            }

            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
            char      name[NI_MAXHOST];
            socklen_t sl = addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            if (getnameinfo((struct sockaddr *)&addr, sl, name, sizeof(name), NULL, 0, NI_NAMEREQD) == 0) {
                pthread_rwlock_wrlock(&hostlock);
                /* the table may have been reset while we were resolving */
                if (hosts[idx].used && addr_eq(&hosts[idx].addr, &addr))
                    snprintf(hosts[idx].name, sizeof(hosts[idx].name), "%s", name);
                pthread_rwlock_unlock(&hostlock);
            }
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        } else {
            pthread_rwlock_unlock(&hostlock);
            usleep(300000);
        }
    }
    return NULL;
}

static int key_eq(const struct flow *f, const struct ring_entry *re, uint16_t key_port) {
    return f->proto == re->meta.proto && f->action == re->meta.action && f->direction == re->meta.dir &&
           f->port == key_port && addr_eq(&f->src, &re->src) && addr_eq(&f->dst, &re->dst);
}

static void unlink_flow(int idx) {
    struct flow *f = &flows[idx];
    uint32_t     b = flow_key_hash(&f->src, &f->dst, f->proto, f->port, f->action, f->direction) & (HASH_BUCKETS - 1);
    for (int *p = &bucket_head[b]; *p != -1; p = &bucket_next[*p]) {
        if (*p == idx) {
            *p = bucket_next[idx];
            return;
        }
    }
}

/* Worker thread only. Never fails: the clock hand always finds a victim within two sweeps. */
struct flow *get_or_create_flow(const struct ring_entry *re, uint16_t key_port) {
    const struct parsed_meta *m = &re->meta;
    uint32_t b = flow_key_hash(&re->src, &re->dst, m->proto, key_port, m->action, m->dir) & (HASH_BUCKETS - 1);
    for (int i = bucket_head[b]; i != -1; i = bucket_next[i]) {
        if (key_eq(&flows[i], re, key_port)) {
            flows[i].accessed = 1;
            return &flows[i];
        }
    }

    pthread_mutex_lock(&flow_lock);
    int idx;
    for (;;) {
        idx = clock_hand;
        clock_hand = (clock_hand + 1) % MAX_ENTRIES;
        if (!flows[idx].used || !flows[idx].accessed)
            break;
        flows[idx].accessed = 0;
    }
    struct flow *f = &flows[idx];
    if (f->used)
        unlink_flow(idx);

    f->src = re->src;
    f->dst = re->dst;
    f->proto = m->proto;
    f->action = m->action;
    f->direction = m->dir;
    f->port = key_port;
    memcpy(f->ifname, re->ifname_raw, sizeof(f->ifname));
    f->ifname[sizeof(f->ifname) - 1] = '\0';
    if (m->subrule_id == (uint32_t)-1)
        snprintf(f->rule_display, sizeof(f->rule_display), "#%u", m->rule_id);
    else
        snprintf(f->rule_display, sizeof(f->rule_display), "#%u.%.16s.%u", m->rule_id, re->ruleset_raw, m->subrule_id);
    atomic_store(&f->packets, 0);
    atomic_store(&f->bytes, 0);
    atomic_store(&f->l3_hdr_bytes, 0);
    atomic_store(&f->l4_hdr_bytes, 0);
    atomic_store(&f->last_us, 0);
    atomic_fetch_add(&f->generation, 1);
    f->accessed = 1;
    f->used = 1;
    bucket_next[idx] = bucket_head[b];
    bucket_head[b] = idx;
    pthread_mutex_unlock(&flow_lock);
    return f;
}
