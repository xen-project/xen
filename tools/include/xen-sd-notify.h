/* SPDX-License-Identifier: MIT-0 */

/*
 * Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/
 *
 * Differences from the upstream copy:
 * - Rename/rework as a drop-in replacement for systemd/sd-daemon.h
 * - Only take the subset Xen cares about
 * - Respect -Wdeclaration-after-statement
 */

#ifndef XEN_SD_NOTIFY
#define XEN_SD_NOTIFY

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static inline void xen_sd_closep(int *fd) {
  if (!fd || *fd < 0)
    return;

  close(*fd);
  *fd = -1;
}

static inline int xen_sd_notify(const char *message) {
  union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_un sun;
  } socket_addr = {
    .sun.sun_family = AF_UNIX,
  };
  size_t path_length, message_length;
  ssize_t written;
  const char *socket_path;
  int __attribute__((cleanup(xen_sd_closep))) fd = -1;

  /* Verify the argument first */
  if (!message)
    return -EINVAL;

  message_length = strlen(message);
  if (message_length == 0)
    return -EINVAL;

  /* If the variable is not set, the protocol is a noop */
  socket_path = getenv("NOTIFY_SOCKET");
  if (!socket_path)
    return 0; /* Not set? Nothing to do */

  /* Only AF_UNIX is supported, with path or abstract sockets */
  if (socket_path[0] != '/' && socket_path[0] != '@')
    return -EAFNOSUPPORT;

  path_length = strlen(socket_path);
  /* Ensure there is room for NUL byte */
  if (path_length >= sizeof(socket_addr.sun.sun_path))
    return -E2BIG;

  memcpy(socket_addr.sun.sun_path, socket_path, path_length);

  /* Support for abstract socket */
  if (socket_addr.sun.sun_path[0] == '@')
    socket_addr.sun.sun_path[0] = 0;

  fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -errno;

  if (connect(fd, &socket_addr.sa, offsetof(struct sockaddr_un, sun_path) + path_length) != 0)
    return -errno;

  written = write(fd, message, message_length);
  if (written != (ssize_t) message_length)
    return written < 0 ? -errno : -EPROTO;

  return 1; /* Notified! */
}

static inline int sd_notify(int unset_environment, const char *message) {
    int r = xen_sd_notify(message);

    if (unset_environment)
        unsetenv("NOTIFY_SOCKET");

    return r;
}

#endif /* XEN_SD_NOTIFY */
