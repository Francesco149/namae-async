#define _GNU_SOURCE

#include "common.c"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>

/* ------------------------------------------------------------- */

#define os_getpid getpid
#define os_write write
#define os_read read
#define os_sleep(ms) usleep(ms * 1000)
#define os_malloc malloc
#define os_free free

#define OS_ERROR_NONE 0

/* OSes that don't have errno should define errno aliases for
   their errors */
int32_t
os_err() {
    return errno;
}

void
os_errstr(char* buf, int32_t cb_buf) {
    strerror_r(errno, buf, cb_buf);
}

/* monotonic time in nanoseconds */
int64_t
os_ntime_mono()
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1e+9 + t.tv_nsec;
}

/* ------------------------------------------------------------- */

#define OS_INVALID_SOCKET -1
typedef int sock_t;

sock_t
udp_sock()
{
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return OS_INVALID_SOCKET;
    }

    return fd;
}

int
sock_block(sock_t s, bool32_t block)
{
    int flags = fcntl(s, F_GETFL, 0);

    if (flags == -1) {
        return -1;
    }

    if (block) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }

    return fcntl(s, F_SETFL, flags);
}

bool32_t
sock_writable(sock_t s, uint32_t timeout_ms)
{
    /* NOTE: this is probably inefficient but simpler to
             use than keeping track of the fd list */

    bool32_t res;
    struct epoll_event ev;
    int epfd;

    epfd = epoll_create(1);

    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLOUT;
    epoll_ctl(epfd, EPOLL_CTL_ADD, s, &ev);

    res = epoll_wait(epfd, &ev, 1, timeout_ms) > 0;
    close(epfd);

    return res;
}

int
os_connect(sock_t s, char const* ipstr, uint16_t port)
{
    /* also inefficient but easier than keeping a sock struct */
    struct sockaddr_in a;

    memset(&a, 0, sizeof(struct sockaddr_in));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = inet_addr(ipstr);

    return connect(s, (struct sockaddr*)&a, sizeof(a));
}

/* ------------------------------------------------------------- */

#include "namae.c"

int main(int argc, char* argv[]) {
    return namae_main(argc, argv);
}
