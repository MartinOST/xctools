/* qmp_helper.c
 *
 * QMP toolstack to stubdomain helper. This simple helper proxies a QMP
 * traffic between a local UNIX socket and a remote V4V QMP chardrv QEMU in
 * the stubdomain.
 *
 * Copyright (c) 2016 Assured Information Security, Ross Philipson <philipsonr@ainfosec.com>
 * Copyright (c) 2014 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "project.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <libv4v.h>

static int qmph_log_level = 0;

/**
 * QMPH_LOG: information to always log (errors & important low-volume events)
 * @param fmt,... printf style arguments
 */
#define QMPH_LOG(fmt, ...)                                           \
do {                                                               \
        syslog(LOG_NOTICE, "[%s:%s:%d] (stubdom-%d) " fmt,         \
               __FILE__, __FUNCTION__, __LINE__, qhs.stubdom_id,   \
                 ##__VA_ARGS__);                                   \
    } while (0)

/**
 * QMPH_DEBUG: debug level
 * @param fmt,... printf style arguments
 */
#define QMPH_DEBUG(fmt, ...)                                             \
    do {                                                               \
        if (qmph_log_level >= 2)                                       \
            QMPH_LOG(fmt, ## __VA_ARGS__);                                  \
    } while (0)

#define V4V_TYPE 'W'
#define V4VIOCSETRINGSIZE       _IOW (V4V_TYPE,  1, uint32_t)

#define V4V_QH_PORT 5100
#define V4V_CHARDRV_RING_SIZE \
  (V4V_ROUNDUP((((4096)*4) - sizeof(v4v_ring_t)-V4V_ROUNDUP(1))))

#define V4V_CHARDRV_NAME  "[v4v-chardrv]"
#define V4V_CHARDRV_HELLO "d2bb2546-155e-11e6-bf28-af0531854834"

struct qmp_helper_state { 
    int stubdom_id;
    int v4v_fd;
    v4v_addr_t remote_addr;
    v4v_addr_t local_addr;
    int unix_fd;
    uint8_t recv_buf[V4V_CHARDRV_RING_SIZE];
};

/* global helper state */
static struct qmp_helper_state qhs;

static int pending_exit = 0;

static void qmph_exit_cleanup(int exit_code)
{
    pending_exit = 1;

    /* TODO deal with open connections */

    /* close local UNIX socket */
    close(qhs.unix_fd);
    qhs.unix_fd = -1;

    /* close v4v channel to stubdom */
    v4v_close(qhs.v4v_fd);
    qhs.v4v_fd = -1;

    closelog();

    exit(exit_code);
}

static int qmph_init_v4v_socket(struct qmp_helper_state *pqhs)
{
    uint32_t v4v_ring_size = V4V_CHARDRV_RING_SIZE;

    pqhs->v4v_fd = v4v_socket(SOCK_DGRAM);
    if (pqhs->v4v_fd == -1) {
        QMPH_LOG("unable to create a v4vsocket");
        return -1;
    }

    pqhs->local_addr.port = V4V_QH_PORT;
    pqhs->local_addr.domain = V4V_DOMID_ANY;

    pqhs->remote_addr.port = V4V_PORT_NONE;
    pqhs->remote_addr.domain = pqhs->stubdom_id;

    /* TODO check for errors */
    ioctl(pqhs->v4v_fd, V4VIOCSETRINGSIZE, &v4v_ring_size);

    if (v4v_bind(pqhs->v4v_fd, &pqhs->local_addr, pqhs->stubdom_id) == -1) {
        QMPH_LOG("unable to bind the v4vsocket");
        v4v_close(pqhs->v4v_fd);
        pqhs->v4v_fd = -1;
        return -1;
    }

    return 0;
}

static int qmph_init_unix_socket(struct qmp_helper_state *pqhs)
{
    /* TODO open the UNIX socket */
    return 0;
}

static void qmph_signal_handler(int sig)
{
    QMPH_LOG("handle signal %d", sig);
    qmph_exit_cleanup(0);
}

int main(int argc, char *argv[])
{
    fd_set rfds;
    int nfds, ret;

    openlog(NULL, LOG_NDELAY, LOG_DAEMON);

    QMPH_LOG("starting %s\n", argv[0]);

    memset(&qhs, 0, sizeof(qhs));

    if (argc != 2) {
        QMPH_LOG("usage: %s <stubdom_id>", argv[0]);
        return -1;
    }

    qhs.stubdom_id = atoi(argv[1]);

    if (qhs.stubdom_id <= 0) {
        QMPH_LOG("bad stubdom id (%d)", qhs.stubdom_id);
        return -1;
    }

    signal(SIGINT, qmph_signal_handler);

    if (qmph_init_v4v_socket(&qhs) != 0) {
        QMPH_LOG("failed to init v4v socket!\n");
        return -1;
    }

    QMPH_LOG("wait for hello from stubdom (%d)", qhs.stubdom_id);

    /* QMP heler must start first and wait for the hello */
    ret = v4v_recvfrom(qhs.v4v_fd, qhs.recv_buf, sizeof(qhs.recv_buf),
                       0, &qhs.remote_addr);
    if (ret < 0) {
        QMPH_LOG("v4v_recvfrom hello failed\n");
        qmph_exit_cleanup(ret);
    }

    if ((ret != sizeof(V4V_CHARDRV_HELLO) - 1) ||
        (strncmp(V4V_CHARDRV_HELLO, (const char*)qhs.recv_buf,
                 sizeof(V4V_CHARDRV_HELLO)))) {
        QMPH_LOG("v4v hello from stubdom failed - ret len: %d\n", ret);
        qmph_exit_cleanup(ret);
    }

    FD_ZERO(&rfds);
    FD_SET(qhs.v4v_fd, &rfds);
    FD_SET(qhs.unix_fd, &rfds);
    nfds = ((qhs.v4v_fd > qhs.unix_fd) ? qhs.v4v_fd : qhs.unix_fd) + 1;

    while (!pending_exit) {

        if (select(nfds, &rfds, NULL, NULL, NULL) == -1) {
            ret = errno;
            QMPH_LOG("failure during select - err: %d\n", ret);
            qmph_exit_cleanup(ret);
        }

        if (FD_ISSET(qhs.v4v_fd, &rfds)) {
        }

        if (FD_ISSET(qhs.unix_fd, &rfds)) {
        }
    }

    QMPH_LOG("exiting...\n");
    qmph_exit_cleanup(0);
    return 0;
}
