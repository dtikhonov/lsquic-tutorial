/* Copyright (c) 2020 LiteSpeed Technologies */
/*
 * tut.c is the example program to illustrate lsquic API usage.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#define EV_STANDALONE 1
#define EV_API_STATIC 1
#include "ev.c"

#include "lsquic.h"

struct tut;
static void tut_process_conns (struct tut *);


static FILE *s_log_fh;

static int
tut_log_buf (void *ctx, const char *buf, size_t len)
{
    FILE *out = ctx;
    fwrite(buf, 1, len, out);
    fflush(out);
    return 0;
}
static const struct lsquic_logger_if logger_if = { tut_log_buf, };


static void
LOG (const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void) vfprintf(s_log_fh, fmt, ap);
    va_end(ap);
    fprintf(s_log_fh, "\n");
}


static SSL_CTX *s_ssl_ctx;

static int
tut_load_cert (const char *cert_file, const char *key_file)
{
    int rv = -1;

    s_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!s_ssl_ctx)
    {
        LOG("SSL_CTX_new failed");
        goto end;
    }
    SSL_CTX_set_min_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(s_ssl_ctx);
    if (1 != SSL_CTX_use_certificate_chain_file(s_ssl_ctx, cert_file))
    {
        LOG("SSL_CTX_use_certificate_chain_file failed");
        goto end;
    }
    if (1 != SSL_CTX_use_PrivateKey_file(s_ssl_ctx, key_file,
                                                            SSL_FILETYPE_PEM))
    {
        LOG("SSL_CTX_use_PrivateKey_file failed");
        goto end;
    }
    rv = 0;

  end:
    if (rv != 0)
    {
        if (s_ssl_ctx)
            SSL_CTX_free(s_ssl_ctx);
        s_ssl_ctx = NULL;
    }
    return rv;
}


static SSL_CTX *
tut_get_ssl_ctx (void *peer_ctx)
{
    return s_ssl_ctx;
}


static int
tut_packets_out (void *packets_out_ctx, const struct lsquic_out_spec *specs,
                                                                unsigned count)
{
    unsigned n;
    int fd, s = 0;
    struct msghdr msg;

    if (0 == count)
        return 0;

    n = 0;
    do
    {
        fd                 = (int) (uint64_t) specs[n].peer_ctx;
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = (AF_INET == specs[n].dest_sa->sa_family ?
                                            sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6)),
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
        msg.msg_flags      = 0;
        msg.msg_control    = NULL;
        msg.msg_controllen = 0;
        s = sendmsg(fd, &msg, 0);
        if (s < 0)
        {
            LOG("sendmsg failed: %s", strerror(errno));
            break;
        }
        ++n;
    }
    while (n < count);

    if (n < count)
        LOG("could not send all of them");    /* TODO */

    if (n > 0)
        return n;
    else
    {
        assert(s < 0);
        return -1;
    }
}


static void
tut_usage (const char *argv0)
{
    const char *name;

    name = strchr(argv0, '/');
    if (name)
        ++name;
    else
        name = argv0;

    fprintf(stdout,
"Usage: %s [options] IP port\n"
"\n"
"   -c cert.file    Certificate.\n"
"   -k key.file     Key file.\n"
"   -f log.file     Log message to this log file.  If not specified, the\n"
"                     are printed to stderr.\n"
"   -L level        Set library-wide log level.  Defaults to 'warn'.\n"
"   -l module=level Set log level of specific module.  Several of these\n"
"                     can be specified via multiple -l flags or by combining\n"
"                     these with comma, e.g. -l event=debug,conn=info.\n"
"   -h              Print this help screen and exit.\n"
    , name);
}


struct tut
{
    /* Common elements needed by both client and server: */
    enum {
        TUT_SERVER  = 1 << 0,
    }                           tut_flags;
    int                         tut_sock_fd;    /* socket */
    ev_io                       tut_sock_w;     /* socket watcher */
    ev_timer                    tut_timer;
    struct ev_loop             *tut_loop;
    lsquic_engine_t            *tut_engine;
    struct sockaddr_storage     tut_local_sas;
    union
    {
        struct client
        {
            ev_io               stdin_w;    /* stdin watcher */
            struct lsquic_conn *conn;
            size_t              sz;         /* Size of bytes read is stored here */
            char                buf[0x100]; /* Read up to this many bytes */
        }   c;
    }                   tut_u;
};


static lsquic_conn_ctx_t *
tut_client_on_new_conn (void *stream_if_ctx, struct lsquic_conn *conn)
{
    struct tut *const tut = stream_if_ctx;
    tut->tut_u.c.conn = conn;
    // ev_io_start(EV_DEFAULT, &tec->tec_stdin_w);
    return NULL;
}


static void
tut_client_on_conn_closed (struct lsquic_conn *conn)
{
}


static lsquic_stream_ctx_t *
tut_client_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    return NULL;
}


static void
tut_client_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
}


static void
tut_client_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
}


static void
tut_client_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
}


static const struct lsquic_stream_if tut_client_callbacks =
{
    .on_new_conn        = tut_client_on_new_conn,
    .on_conn_closed     = tut_client_on_conn_closed,
    .on_new_stream      = tut_client_on_new_stream,
    .on_read            = tut_client_on_read,
    .on_write           = tut_client_on_write,
    .on_close           = tut_client_on_close,
};


static lsquic_conn_ctx_t *
tut_server_on_new_conn (void *stream_if_ctx, struct lsquic_conn *conn)
{
    struct tut *const tut = stream_if_ctx;

    LOG("created new connection");
    return (void *) tut;     /* Pointer to tut is the connection context */
}


static void
tut_server_on_conn_closed (lsquic_conn_t *conn)
{
    LOG("closed connection");
}


struct tut_server_stream_ctx
{
    size_t           tssc_sz;            /* Number of bytes in tsc_buf */
    unsigned char    tssc_buf[0x100];    /* Bytes read in from client */
};


static lsquic_stream_ctx_t *
tut_server_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct tut_server_stream_ctx *tssc;

    /* Allocate a new buffer per stream.  There is no reason why the echo
     * server could not process several echo streams at the same time.
     */
    tssc = malloc(sizeof(*tssc));
    if (!tssc)
    {
        LOG("cannot allocate server stream context");
        lsquic_conn_abort(lsquic_stream_conn(stream));
        return NULL;
    }

    tssc->tssc_sz = 0;
    lsquic_stream_wantread(stream, 1);
    LOG("created new echo stream -- want to read");
    return (void *) tssc;
}


/* Read until newline and then echo it back */
static void
tut_server_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct tut_server_stream_ctx *const tssc = (void *) h;
    ssize_t nread;
    unsigned char buf[1];

    nread = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nread > 0)
    {
        tssc->tssc_buf[ tssc->tssc_sz ] = buf[0];
        ++tssc->tssc_sz;
        if (buf[0] == (unsigned char) '\n'
                            || tssc->tssc_sz == sizeof(tssc->tssc_buf))
        {
            LOG("read newline or filled buffer, switch to writing");
            lsquic_stream_wantread(stream, 0);
            lsquic_stream_wantwrite(stream, 1);
        }
    }
    else if (nread == 0)
    {
        LOG("read EOF");
        lsquic_stream_shutdown(stream, 0);
        if (tssc->tssc_sz)
            lsquic_stream_wantwrite(stream, 1);
    }
    else
    {
        /* This should not happen */
        LOG("error reading from stream (errno: %d) -- abort connection", errno);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}


static void
tut_server_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct tut_server_stream_ctx *const tssc = (void *) h;
    ssize_t nw;

    assert(tssc->tssc_sz > 0);
    nw = lsquic_stream_write(stream, tssc->tssc_buf, tssc->tssc_sz);
    if (nw > 0)
    {
        tssc->tssc_sz -= (size_t) nw;
        if (tssc->tssc_sz == 0)
        {
            LOG("wrote all %zd bytes to stream, switch to reading",
                                                            (size_t) nw);
            (void) lsquic_stream_flush(stream);
            lsquic_stream_wantwrite(stream, 0);
            lsquic_stream_wantread(stream, 1);
        }
        else
        {
            memmove(tssc->tssc_buf, tssc->tssc_buf + nw, tssc->tssc_sz);
            LOG("wrote %zd bytes to stream, still have %zd bytes to write",
                                                (size_t) nw, tssc->tssc_sz);
        }
    }
    else
    {
        /* When `on_write()' is called, the library guarantees that at least
         * something can be written.  If not, that's an error whether 0 or -1
         * is returned.
         */
        LOG("stream_write() returned %ld, abort connection", (long) nw);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}


static void
tut_server_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct tut_server_stream_ctx *const tssc = (void *) h;
    free(tssc);
    LOG("stream closed");
}


static const struct lsquic_stream_if tut_server_callbacks =
{
    .on_new_conn        = tut_server_on_new_conn,
    .on_conn_closed     = tut_server_on_conn_closed,
    .on_new_stream      = tut_server_on_new_stream,
    .on_read            = tut_server_on_read,
    .on_write           = tut_server_on_write,
    .on_close           = tut_server_on_close,
};


static void
tut_read_stdin (EV_P_ ev_io *w, int revents)
{
    struct tut *const tut = w->data;
    ssize_t nr;

    nr = read(w->fd, tut->tut_u.c.buf, sizeof(tut->tut_u.c.buf));
    if (nr > 0)
    {
        tut->tut_u.c.sz = (size_t) nr;
        ev_io_stop(EV_A_ w);
    }
    else
    {
        if (nr < 0)
            LOG("error reading from stdin: %s", strerror(errno));
        ev_break(tut->tut_loop, EVBREAK_ONE);
    }
}


static int
tut_set_nonblocking (int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (-1 == flags)
        return -1;
    flags |= O_NONBLOCK;
    if (0 != fcntl(fd, F_SETFL, flags))
        return -1;

    return 0;
}


static void
tut_timer_expired (EV_P_ ev_timer *timer, int revents)
{
    tut_process_conns(timer->data);
}


static void
tut_process_conns (struct tut *tut)
{
    int diff;
    ev_tstamp timeout;

    ev_timer_stop(tut->tut_loop, &tut->tut_timer);
    lsquic_engine_process_conns(tut->tut_engine);

    if (lsquic_engine_earliest_adv_tick(tut->tut_engine, &diff))
    {
        if (diff < 0 || (unsigned) diff < LSQUIC_DF_CLOCK_GRANULARITY)
            timeout = (ev_tstamp) LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
        else
            timeout = ((ev_tstamp) diff / 1000000)
                            + ((ev_tstamp) (diff % 1000000) / 1000000);
        ev_timer_init(&tut->tut_timer, tut_timer_expired, timeout, 0.);
        ev_timer_start(tut->tut_loop, &tut->tut_timer);
    }
}


static void
tut_read_socket (EV_P_ ev_io *w, int revents)
{
    struct tut *const tut = w->data;
    ssize_t nread;
    struct sockaddr_storage peer_sas;
    unsigned char buf[0x1000];
    struct iovec vec[1] = {{ buf, sizeof(buf) }};

    struct msghdr msg = {
        .msg_name       = &peer_sas,
        .msg_namelen    = sizeof(peer_sas),
        .msg_iov        = vec,
        .msg_iovlen     = 1,
        .msg_control    = NULL,
        .msg_controllen = 0,
    };
    nread = recvmsg(w->fd, &msg, 0);
    if (-1 == nread) {
        if (!(EAGAIN == errno || EWOULDBLOCK == errno))
            LOG("recvmsg: %s", strerror(errno));
        return;
    }

    (void) lsquic_engine_packet_in(tut->tut_engine, buf, nread,
        /* Very simple to begin with: use single local address */
        (struct sockaddr *) &tut->tut_local_sas,
        (struct sockaddr *) &peer_sas,
        (void *) (uintptr_t) w->fd,
        0 /* TODO: read ECN from ancillary data */);

    tut_process_conns(tut);
}


int
main (int argc, char **argv)
{
    struct lsquic_engine_api eapi;
    const char *cert_file = NULL, *key_file = NULL;
    int opt, is_server;
    socklen_t socklen;
    struct tut tut;
    union {
        struct sockaddr     sa;
        struct sockaddr_in  addr4;
        struct sockaddr_in6 addr6;
    } addr;

    s_log_fh = stderr;

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER|LSQUIC_GLOBAL_CLIENT))
    {
        fprintf(stderr, "global initialization failed\n");
        exit(EXIT_FAILURE);
    }

    memset(&tut, 0, sizeof(tut));

    while (opt = getopt(argc, argv, "c:f:k:l:L:h"), opt != -1)
    {
        switch (opt)
        {
        case 'c':
            cert_file = optarg;
            break;
        case 'f':
            s_log_fh = fopen(optarg, "ab");
            if (!s_log_fh)
            {
                perror("cannot open log file for writing");
                exit(EXIT_FAILURE);
            }
            break;
        case 'k':
            key_file = optarg;
            break;
        case 'l':
            if (0 != lsquic_logger_lopt(optarg))
            {
                fprintf(stderr, "error processing -l option\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'L':
            if (0 != lsquic_set_log_level(optarg))
            {
                fprintf(stderr, "error processing -L option\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'h':
            tut_usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        default:
            exit(EXIT_FAILURE);
            break;
        }
    }

    if (optind + 1 >= argc)
    {
        LOG("please specify IP address and port number");
        exit(EXIT_FAILURE);
    }

    /* Parse IP address and port number */
    if (inet_pton(AF_INET, argv[optind], &addr.addr4.sin_addr))
    {
        addr.addr4.sin_family = AF_INET;
        addr.addr4.sin_port   = htons(atoi(argv[optind + 1]));
    }
    else if (memset(&addr.addr6, 0, sizeof(addr.addr6)),
       inet_pton(AF_INET6, argv[optind], &addr.addr6.sin6_addr))
    {
        addr.addr6.sin6_family = AF_INET;
        addr.addr6.sin6_port   = htons(atoi(argv[optind + 1]));
    }
    else
    {
        LOG("`%s' is not a valid IP address", argv[optind]);
        exit(EXIT_FAILURE);
    }

    /* Specifying certificate and key files indicates server mode */
    if (cert_file || key_file)
    {
        if (!(cert_file && key_file))
        {
            LOG("Specify both cert (-c) and key (-k) files");
            exit(EXIT_FAILURE);
        }
        if (0 != tut_load_cert(cert_file, key_file))
        {
            LOG("Cannot load certificate");
            exit(EXIT_FAILURE);
        }
        tut.tut_flags |= TUT_SERVER;
    }

    /* Initialize event loop */
    tut.tut_loop = EV_DEFAULT;
    tut.tut_sock_fd = socket(addr.sa.sa_family, SOCK_DGRAM, 0);

    /* Set up socket */
    if (tut.tut_sock_fd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if (0 != tut_set_nonblocking(tut.tut_sock_fd))
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    if (tut.tut_flags & TUT_SERVER)
    {
        socklen = sizeof(addr);
        if (0 != bind(tut.tut_sock_fd, &addr.sa, socklen))
        {
            perror("bind");
            exit(EXIT_FAILURE);
        }
        memcpy(&tut.tut_local_sas, &addr, sizeof(addr));
    }
    else
    {
        tut.tut_local_sas.ss_family = addr.sa.sa_family;
        socklen = sizeof(tut.tut_local_sas);
        if (0 != bind(tut.tut_sock_fd,
                        (struct sockaddr *) &tut.tut_local_sas, socklen))
        {
            perror("bind");
            exit(EXIT_FAILURE);
        }
        ev_init(&tut.tut_timer, tut_timer_expired);
    }
    ev_io_init(&tut.tut_sock_w, tut_read_socket, tut.tut_sock_fd, EV_READ);
    ev_io_start(tut.tut_loop, &tut.tut_sock_w);

    /* Initialize logging */
    lsquic_logger_init(&logger_if, s_log_fh, LLTS_HHMMSSUS);

    /* Initialize callbacks */
    memset(&eapi, 0, sizeof(eapi));
    eapi.ea_packets_out = tut_packets_out;
    eapi.ea_packets_out_ctx = &tut;
    eapi.ea_stream_if   = tut.tut_flags & TUT_SERVER
                            ? &tut_server_callbacks : &tut_client_callbacks;
    eapi.ea_stream_if_ctx = &tut;
    eapi.ea_get_ssl_ctx   = tut_get_ssl_ctx;

    tut.tut_engine = lsquic_engine_new(tut.tut_flags & TUT_SERVER
                                            ? LSENG_SERVER : 0, &eapi);
    if (!tut.tut_engine)
    {
        LOG("cannot create engine");
        exit(EXIT_FAILURE);
    }

    tut.tut_timer.data = &tut;
    tut.tut_sock_w.data = &tut;
    if (tut.tut_flags & TUT_SERVER)
    {
    }
    else
    {
        if (0 != tut_set_nonblocking(STDIN_FILENO))
        {
            perror("fcntl(stdin)");
            exit(EXIT_FAILURE);
        }
        ev_io_init(&tut.tut_u.c.stdin_w, tut_read_stdin, STDIN_FILENO,
                                                                EV_READ);
        tut.tut_u.c.conn = lsquic_engine_connect(
            tut.tut_engine, N_LSQVER,
            (struct sockaddr *) &tut.tut_local_sas, &addr.sa,
            (void *) (uintptr_t) tut.tut_sock_fd,  /* Peer ctx */
            NULL, NULL, 0, NULL, 0, NULL, 0);
        if (!tut.tut_u.c.conn)
        {
            LOG("cannot create connection");
            exit(EXIT_FAILURE);
        }
        tut_process_conns(&tut);
    }
    ev_run(tut.tut_loop, 0);

    lsquic_engine_destroy(tut.tut_engine);
    lsquic_global_cleanup();
    exit(EXIT_SUCCESS);
}
