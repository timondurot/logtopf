#include "net_utils.h"
#include <stdint.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct internal_net {
    struct in_addr addr;
    struct in_addr mask;
};

struct internal_net_v6 {
    struct in6_addr addr;
    struct in6_addr mask;
};

static struct internal_net    *v4_nets = NULL;
static int                     v4_count = 0;
static struct internal_net_v6 *v6_nets = NULL;
static int                     v6_count = 0;

static void *expand(void *ptr, int *cap, size_t elem_size) {
    int   new_cap = (*cap == 0) ? 4 : (*cap) * 2;
    void *np = realloc(ptr, new_cap * elem_size);
    if (!np)
        return NULL;
    *cap = new_cap;
    return np;
}

void init_internal_nets(void) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    int v4_cap = 0, v6_cap = 0;
    v4_nets = NULL;
    v6_nets = NULL;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (v4_count >= v4_cap) {
                void *np = expand(v4_nets, &v4_cap, sizeof(struct internal_net));
                if (!np)
                    continue;
                v4_nets = np;
            }
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            struct sockaddr_in *sim = (struct sockaddr_in *)ifa->ifa_netmask;
            v4_nets[v4_count].addr = sin->sin_addr;
            /* no netmask (point-to-point): treat as a host route, not as 0.0.0.0/0 */
            v4_nets[v4_count].mask = sim ? sim->sin_addr : (struct in_addr){ INADDR_BROADCAST };
            v4_count++;
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            if (v6_count >= v6_cap) {
                void *np = expand(v6_nets, &v6_cap, sizeof(struct internal_net_v6));
                if (!np)
                    continue;
                v6_nets = np;
            }
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            struct sockaddr_in6 *sim6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
            v6_nets[v6_count].addr = sin6->sin6_addr;
            if (sim6)
                v6_nets[v6_count].mask = sim6->sin6_addr;
            else
                memset(&v6_nets[v6_count].mask, 0xff, sizeof(v6_nets[v6_count].mask));
            v6_count++;
        }
    }
    freeifaddrs(ifaddr);
}

int is_internal_addr(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        for (int i = 0; i < v4_count; i++)
            if ((sin->sin_addr.s_addr & v4_nets[i].mask.s_addr) == (v4_nets[i].addr.s_addr & v4_nets[i].mask.s_addr))
                return 1;
    } else if (addr->ss_family == AF_INET6) {
        const uint64_t *s6 = (const uint64_t *)((struct sockaddr_in6 *)addr)->sin6_addr.s6_addr;
        for (int i = 0; i < v6_count; i++) {
            const uint64_t *m6 = (const uint64_t *)v6_nets[i].mask.s6_addr;
            const uint64_t *a6 = (const uint64_t *)v6_nets[i].addr.s6_addr;
            if ((s6[0] & m6[0]) == (a6[0] & m6[0]) && (s6[1] & m6[1]) == (a6[1] & m6[1]))
                return 1;
        }
    }
    return 0;
}

void cleanup_internal_nets(void) {
    free(v4_nets);
    free(v6_nets);
}
