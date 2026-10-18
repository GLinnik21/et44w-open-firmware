#include "net_listen.h"

#include "lwip/sockets.h"

int net_listen(uint16_t port, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    (void) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY };
    if (bind(fd, (struct sockaddr*) &addr, sizeof addr) < 0 || listen(fd, backlog) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}
