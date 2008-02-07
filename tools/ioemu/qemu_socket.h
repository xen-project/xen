/* headers to use the BSD sockets */
#ifndef QEMU_SOCKET_H
#define QEMU_SOCKET_H

#ifdef _WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define socket_error() WSAGetLastError()
#undef EINTR
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EINTR       WSAEINTR
#define EINPROGRESS WSAEINPROGRESS

#ifndef NO_UNIX_SOCKETS
#define NO_UNIX_SOCKETS 1
#endif

#else

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifndef NO_UNIX_SOCKETS
#include <sys/un.h>
#endif

#define socket_error() errno
#define closesocket(s) close(s)

#endif /* !_WIN32 */

void socket_set_nonblock(int fd);

#endif /* QEMU_SOCKET_H */
