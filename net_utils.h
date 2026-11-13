#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <netinet/in.h>
#include <sys/socket.h>

void init_internal_nets(void);
int is_internal_addr(const struct sockaddr_storage *addr);
void cleanup_internal_nets(void);

#endif
