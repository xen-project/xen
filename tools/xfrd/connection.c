#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "connection.h"
#include "file_stream.h"
#include "lzi_stream.h"
#include "sxpr_parser.h"

#define dprintf(fmt, args...) fprintf(stdout, "[DEBUG] %s" fmt, __FUNCTION__, ##args)
#define wprintf(fmt, args...) fprintf(stderr, "[WARN]  %s" fmt, __FUNCTION__, ##args)
#define iprintf(fmt, args...) fprintf(stdout, "[INFO]  %s" fmt, __FUNCTION__, ##args)
#define eprintf(fmt, args...) fprintf(stderr, "[ERROR] %s" fmt, __FUNCTION__, ##args)

/** Compress magic header. */
char compress_magic[2] = { 0x1f, 0x8b };

/** Plain magic header. */
char plain_magic[2] = { 0x0, 0x0 };

int Conn_read_header(int sock, int *flags){
    int err = 0;
    char magic[2] = {};
    int k, n = sizeof(magic);
    k = read(sock, magic, n);
    if(k != n){
        err = -EINVAL;
        goto exit;
    }
    dprintf("> magic={ 0x%x, 0x%x }\n", magic[0], magic[1]);
    if(magic[0] == compress_magic[0] && magic[1] == compress_magic[1]){
        *flags |= CONN_READ_COMPRESS;
        dprintf("> Using compress read.\n");
    } else {
        dprintf("> Using plain read.\n");
    }
  exit:
    return err;
}

int Conn_write_header(int sock, int flags){
    int err = 0;
    if(flags & CONN_WRITE_COMPRESS){
        dprintf("> Using compress write.\n");
        err = write(sock, compress_magic, 2);
    } else { 
        dprintf("> Using plain write.\n");
       err = write(sock, plain_magic, 2);
    }
    if(err == 2) err = 0;
    return err;
}

/** Initialize a file stream from a file desciptor.
 *
 * @param fd file descriptor
 * @param mode file mode
 * @param flags control compression and buffering
 * @param io return parameter for the stream
 * @return 0 on success, error code otherwise
 */
int stream_init(int fd, const char *mode, int flags, int compress, IOStream **io){
    int err = 0;
    dprintf(">mode=%s flags=%x compress=%d\n", mode, flags, compress);
    if(compress){
        *io = lzi_stream_fdopen(fd, mode);
    } else {
        *io = file_stream_fdopen(fd, mode);
    }
    if(!*io){
        err = -errno;
        perror("fdopen");
        goto exit;
    }
    if(1 && (flags & CONN_NOBUFFER)){
        // Make unbuffered.
        dprintf("> unbuffer...\n");
        err = file_stream_setvbuf((compress ? lzi_stream_io(*io) : *io), NULL, _IONBF, 0);
        if(err){
            err = -errno;
            perror("setvbuf");
            goto exit;
        }
    }
  exit:
    if(err && *io){
        dprintf("> close err=%d\n", err);
        IOStream_close(*io);
        *io = NULL;
    }
    dprintf("< err=%d\n", err);
    return err;
}
    
/** Initialize a connection.
 *
 * @param conn connection
 * @param flags
 * @param sock socket
 * @param ipaddr ip address
 * @return 0 on success, error code otherwise
 */
int Conn_init(Conn *conn, int flags, int sock, struct sockaddr_in addr){
    int err = 0;
    dprintf("> flags=%x\n", flags);
    conn->addr = addr;
    conn->sock = sock;
    dprintf("> write stream...\n");
    err = stream_init(sock, "w", flags, (flags & CONN_WRITE_COMPRESS), &conn->out);
    if(err) goto exit;
    IOStream_flush(conn->out);
    dprintf("> read stream...\n");
    err = stream_init(sock, "r", flags, (flags & CONN_READ_COMPRESS) , &conn->in);
    if(err) goto exit;
  exit:
    if(err) eprintf("< err=%d\n", err);
    return err;
}

/** Open a connection.
 *
 * @param conn connection
 * @param flags
 * @param ipaddr ip address to connect to
 * @param port port
 * @return 0 on success, error code otherwise
 */
int Conn_connect(Conn *conn, int flags, struct in_addr ipaddr, uint16_t port){
    int err = 0;
    int sock;
    struct sockaddr_in addr_in;
    struct sockaddr *addr = (struct sockaddr *)&addr_in;
    socklen_t addr_n = sizeof(addr_in);
    dprintf("> addr=%s:%d\n", inet_ntoa(ipaddr), ntohs(port));
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        err = -errno;
        goto exit;
    }
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr = ipaddr;
    addr_in.sin_port = port;
    err = connect(sock, addr, addr_n);
    if(err) goto exit;
    //err = Conn_write_header(sock, flags);
    //if(err < 0) goto exit;
    err = Conn_init(conn, flags, sock, addr_in);
  exit:
    if(err) eprintf("< err=%d\n", err);
    return err;
}

/** Close a connection.
 *
 * @param conn connection
 */
void Conn_close(Conn *conn){
    if(conn->in) IOStream_close(conn->in);
    if(conn->out) IOStream_close(conn->out);
    shutdown(conn->sock, 2);
}

int Conn_sxpr(Conn *conn, Sxpr *sxpr){
    int err = 0;
    Sxpr val = ONONE;
    int c = 0;

    dprintf(">\n");
    if(!conn->parser){
        conn->parser = Parser_new();
        Parser_set_error_stream(conn->parser, iostdout);
    }
    while(!err && c >= 0 && !Parser_ready(conn->parser)){
        c = IOStream_getc(conn->in);
        printf("%c", (char)c);
        if(c < 0){
            err = Parser_input_eof(conn->parser);
        } else {
            err = Parser_input_char(conn->parser, c);
        }
    }
    if(Parser_ready(conn->parser)){
        val = Parser_get_val(conn->parser);
    }
    if(err){
        objfree(val);
        val = ONONE;
    }
    *sxpr = val;
    dprintf("< err=%d\n", err);
    return err;
}
