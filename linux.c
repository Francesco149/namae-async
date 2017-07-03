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

struct sock
{
    int fd;
    int epfd;
};

#define OS_INVALID_SOCKET (sock_t)-1

typedef struct sock* sock_t;

#define sock_write(s, buf, n) write(s->fd, buf, n)
#define  sock_read(s, buf, n)  read(s->fd, buf, n)

sock_t
udp_sock()
{
    struct sock* s;
    int fd;
    int epfd;
    struct epoll_event ev;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return OS_INVALID_SOCKET;
    }

    epfd = epoll_create(1);
    if (epfd < 0) {
        s = OS_INVALID_SOCKET;
        goto cleanup;
    }

    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLOUT;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        s = OS_INVALID_SOCKET;
        goto cleanup;
    }

    s = os_malloc(sizeof(struct sock));
    if (!s) {
        s = OS_INVALID_SOCKET;
        goto cleanup;
    }

    s->fd = fd;
    s->epfd = epfd;

cleanup:
    if (s == OS_INVALID_SOCKET)
    {
        if (epfd != -1) {
            close(epfd);
        }

        if (fd != -1) {
            close(fd);
        }
    }

    return s;
}

void
sock_close(sock_t s)
{
    if (!s) {
        return;
    }

    close(s->fd);
    close(s->epfd);
    os_free(s);
}

int
sock_block(sock_t s, bool32_t block)
{
    int flags = fcntl(s->fd, F_GETFL, 0);

    if (flags == -1) {
        return -1;
    }

    if (block) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }

    return fcntl(s->fd, F_SETFL, flags);
}

bool32_t
sock_writable(sock_t s, uint32_t timeout_ms)
{
    bool32_t res;
    struct epoll_event ev;
    res = epoll_wait(s->epfd, &ev, 1, timeout_ms) > 0;

    /* NOTE: actually check what events are set when I add
             more pollable things */

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

    return connect(s->fd, (struct sockaddr*)&a, sizeof(a));
}

/* ------------------------------------------------------------- */

#include "namae.c"

int main(int argc, char* argv[]) {
    return namae_main(argc, argv);
}
