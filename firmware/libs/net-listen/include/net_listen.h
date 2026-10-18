// Shared TCP listener setup for the module's small socket servers (OTA, netlog, httpd).
#ifndef NET_LISTEN_H
#define NET_LISTEN_H

#include <stdint.h>

// IPv4 listening socket on port (any address, SO_REUSEADDR). Returns the fd, or -1 (e.g. lwIP not up yet).
int net_listen(uint16_t port, int backlog);

#endif
