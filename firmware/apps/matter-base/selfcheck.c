#include "selfcheck.h"

#include "lwip/sockets.h"

bool selfcheck_tcp_answers(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return false;
    }
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port),
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bool ok = connect(fd, (struct sockaddr*) &addr, sizeof addr) == 0;
    close(fd);
    return ok;
}
