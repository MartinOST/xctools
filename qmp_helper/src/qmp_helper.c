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
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <libv4v.h>

/**
 * QMPH_LOG: information to always log (errors & important low-volume events)
 * @param fmt,... printf style arguments
 */
#define QMPH_LOG(fmt, ...)						\
  do {									\
    syslog(LOG_NOTICE, "qmp-helper [%s:%s:%d] (stubdom-%d) " fmt,	\
	   __FILE__, __FUNCTION__, __LINE__, qhs.stubdom_id,		\
	   ##__VA_ARGS__);						\
  } while (0)

#define V4V_TYPE 'W'
#define V4VIOCSETRINGSIZE       _IOW (V4V_TYPE,  1, uint32_t)

#define V4V_QH_PORT 5100
#define V4V_CHARDRV_PORT 15100
#define V4V_CHARDRV_RING_SIZE						\
  (V4V_ROUNDUP((((4096)*4) - sizeof(v4v_ring_t)-V4V_ROUNDUP(1))))

#define V4V_CHARDRV_NAME  "[v4v-chardrv]"

struct qmp_helper_state { 
  int stubdom_id;
  int v4v_fd;
  v4v_addr_t remote_addr;
  v4v_addr_t local_addr;
  int unix_fd;
  int listen_fd;
  uint8_t msg_buf[V4V_CHARDRV_RING_SIZE];
  struct sockaddr_un un;
};

/* global helper state */
static struct qmp_helper_state qhs;

static int pending_exit = 0;

static void qmph_exit_cleanup(int exit_code)
{
  pending_exit = 1;

  /* Done listening */
  close(qhs.listen_fd);

  //  unlink(un.sun_path);
  
  /* close connection on the UNIX socket */
  close(qhs.unix_fd);
  qhs.unix_fd = -1;

  /* close v4v channel to stubdom */
  v4v_close(qhs.v4v_fd);
  qhs.v4v_fd = -1;

  closelog();

  exit(exit_code);
}

static int qmph_unix_to_v4v(struct qmp_helper_state *pqhs)
{
  int ret, rcv;

  rcv = read(pqhs->unix_fd, pqhs->msg_buf, sizeof(pqhs->msg_buf));
  if (rcv < 0) {
    QMPH_LOG("ERROR read(unix_fd) failed (%s) - %d.\n",
	     strerror(errno), rcv);
    return rcv;
  }
  else if (rcv == 0) {
    QMPH_LOG("read(unix_fd) recieved EOF.\n");
    //qmph_exit_cleanup(0);
    return ENOTCONN;
  }

  ret = v4v_sendto(pqhs->v4v_fd, pqhs->msg_buf,
		   rcv, 0, &pqhs->remote_addr);
  if (ret != rcv) {
    QMPH_LOG("ERROR v4v_sendto() failed (%s) - %d %d.\n",
	     strerror(errno), ret, rcv);
    return -1;
  }

  return 0;
}

static int qmph_v4v_to_unix(struct qmp_helper_state *pqhs)
{
  int ret, rcv;

  rcv = v4v_recvfrom(pqhs->v4v_fd, pqhs->msg_buf, sizeof(pqhs->msg_buf),
		     0, &pqhs->remote_addr);
  if (rcv < 0) {
    QMPH_LOG("ERROR v4v_recvfrom() failed (%s) - %d.\n",
	     strerror(errno), rcv);
    return rcv;
  }

  ret = write(pqhs->unix_fd, pqhs->msg_buf, rcv);
  if (ret < 0) {
    QMPH_LOG("ERROR write(unix_fd) failed (%s) - %d.\n",
	     strerror(errno), ret);
    return ret;
  }

  return 0;
}

static int qmph_init_v4v_socket(struct qmp_helper_state *pqhs)
{
  uint32_t v4v_ring_size = V4V_CHARDRV_RING_SIZE;

  pqhs->v4v_fd = v4v_socket(SOCK_DGRAM);
  if (pqhs->v4v_fd == -1) {
    QMPH_LOG("ERROR unable to create a v4vsocket");
    return -1;
  }

  pqhs->local_addr.port = V4V_QH_PORT;
  pqhs->local_addr.domain = 0;

  pqhs->remote_addr.port = V4V_CHARDRV_PORT;
  pqhs->remote_addr.domain = pqhs->stubdom_id;

  if (ioctl(pqhs->v4v_fd, V4VIOCSETRINGSIZE, &v4v_ring_size) == -1) {
    QMPH_LOG("ERROR unable to send ioctl V4VIOCSETRINGSIZE to v4vsocket");
    goto err;
  }

  if (v4v_bind(pqhs->v4v_fd, &pqhs->local_addr, pqhs->stubdom_id) == -1) {
    QMPH_LOG("ERROR unable to bind the v4vsocket");
    goto err;
  }

  return 0;

 err:
  v4v_close(pqhs->v4v_fd);
  pqhs->v4v_fd = -1;
  return -1;
}

static void do_listen_and_accept(struct qmp_helper_state *pqhs)
{
  socklen_t len = sizeof(struct sockaddr_un);
  int cfd;
  
  QMPH_LOG("Entered do_listen_and accept");
  
  if (listen(pqhs->listen_fd, 1) < 0) {
    QMPH_LOG("ERROR listen socket failed - err: %d", errno);
    goto err;
  }

  QMPH_LOG("Listen succeeded");

  cfd = accept(pqhs->listen_fd, (struct sockaddr*)&(pqhs->un), &len);
  if (cfd < 0) {
    QMPH_LOG("ERROR listen socket failed - err: %d", errno);
    goto err;
  }
  QMPH_LOG("Accept succeeded");

  pqhs->unix_fd = cfd;

  QMPH_LOG("Accepted the connection cfd: %d", cfd);

  return;
 err:
  close(pqhs->listen_fd);
}

static int qmph_init_unix_socket(struct qmp_helper_state *pqhs)
{
  /* By default the helper creates a Unix socket as if QEMU were called with:
   * -qmp unix:/var/run/xen/qmp-libxl-<domid>,server,nowait
   */

  pqhs->unix_fd = -1;

  /* First step, start the listener then wait for a connection */
  pqhs->listen_fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if (pqhs->listen_fd < 0) {
    QMPH_LOG("ERROR create socket failed - err: %d", errno);
    return -1;
  }

  memset(&(pqhs->un), 0, sizeof(pqhs->un));
  pqhs->un.sun_family = AF_UNIX;
  snprintf(pqhs->un.sun_path, sizeof(pqhs->un.sun_path),
	   "/var/run/xen/qmp-libxl-%d", pqhs->stubdom_id);

  if (bind(pqhs->listen_fd, (struct sockaddr*)&(pqhs->un), sizeof(pqhs->un)) < 0) {
    QMPH_LOG("ERROR bind socket failed - err: %d", errno);
    goto err;
  }

  do_listen_and_accept(pqhs);
  
  return 0;

 err:
  close(pqhs->listen_fd);
  return -1;
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

  if (qhs.stubdom_id < 0) {
    QMPH_LOG("ERROR bad stubdom id (%d)", qhs.stubdom_id);
    return -1;
  }

  signal(SIGINT, qmph_signal_handler);

  ret = qmph_init_v4v_socket(&qhs);
  if (ret) {
    QMPH_LOG("ERROR failed to init v4v socket - ret: %d\n", ret);
    return -1;
  }

  QMPH_LOG("v4v ready, wait for a connection...");

  /* Ready to listen and accept one connection. Note this will block on
   * accept until connected.
   */
  ret = qmph_init_unix_socket(&qhs);
  if (ret) {
    QMPH_LOG("ERROR failed to init unix socket - ret: %d\n", ret);
    qmph_exit_cleanup(ret);
  }

  while (!pending_exit) {

    FD_ZERO(&rfds);
    FD_SET(qhs.v4v_fd, &rfds);
    FD_SET(qhs.unix_fd, &rfds);
    nfds = ((qhs.v4v_fd > qhs.unix_fd) ? qhs.v4v_fd : qhs.unix_fd) + 1;

    if (select(nfds, &rfds, NULL, NULL, NULL) == -1) {
      ret = errno;
      QMPH_LOG("ERROR failure during select - err: %d\n", ret);
      qmph_exit_cleanup(ret);
    }

    if (FD_ISSET(qhs.unix_fd, &rfds)) {
      ret = qmph_unix_to_v4v(&qhs);
      if(ret == ENOTCONN)
	do_listen_and_accept(&qhs);
      else if (ret!=0)
	break; /* abject misery */
    }

    if (FD_ISSET(qhs.v4v_fd, &rfds)) {
      if (qmph_v4v_to_unix(&qhs))
	break; /* total death */
    }
  }

  QMPH_LOG("exiting...\n");
  qmph_exit_cleanup(0);
  return 0;
}
