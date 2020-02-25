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
}


static SSL_CTX *s_ssl_ctx;

static int
tut_load_cert (const char *cert_file, const char *key_file)
{
    int rv = -1;

    s_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!s_ssl_ctx)
    {
        fprintf(stderr, "SSL_CTX_new failed\n");
        goto end;
    }
    SSL_CTX_set_min_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(s_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(s_ssl_ctx);
    if (1 != SSL_CTX_use_certificate_chain_file(s_ssl_ctx, cert_file))
    {
        fprintf(stderr, "SSL_CTX_use_certificate_chain_file failed\n");
        goto end;
    }
    if (1 != SSL_CTX_use_PrivateKey_file(s_ssl_ctx, key_file,
                                                            SSL_FILETYPE_PEM))
    {
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file failed\n");
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
            fprintf(stderr, "sendmsg failed: %s\n", strerror(errno));
            break;
        }
        ++n;
    }
    while (n < count);

    if (n < count)
        fprintf(stderr, "could not send all of them\n");    /* TODO */

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
            fprintf(stderr, "error reading from stdin: %s\n", strerror(errno));
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
tut_process_conns (struct tut *tut)
{
    int diff;
    ev_tstamp timeout;

    lsquic_engine_process_conns(tut->tut_engine);

    if (lsquic_engine_earliest_adv_tick(tut->tut_engine, &diff))
    {
        if (diff < 0 || (unsigned) diff < LSQUIC_DF_CLOCK_GRANULARITY)
            timeout = (ev_tstamp) LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
        else
            timeout = ((ev_tstamp) diff / 1000000)
                            + ((ev_tstamp) (diff % 1000000) / 1000000);
        ev_timer_set(&tut->tut_timer, timeout, 0.);
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
            fprintf(stderr, "recvmsg: %s\n", strerror(errno));
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


static void
tut_timer_expired (EV_P_ ev_timer *timer, int revents)
{
    tut_process_conns(timer->data);
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
    } peer;

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
        fprintf(stderr, "please specify IP address and port number\n");
        exit(EXIT_FAILURE);
    }

    /* Parse IP address and port number */
    if (inet_pton(AF_INET, argv[optind], &peer.addr4.sin_addr))
    {
        peer.addr4.sin_family = AF_INET;
        peer.addr4.sin_port   = htons(atoi(argv[optind + 1]));
    }
    else if (memset(&peer.addr6, 0, sizeof(peer.addr6)),
       inet_pton(AF_INET6, argv[optind], &peer.addr6.sin6_addr))
    {
        peer.addr6.sin6_family = AF_INET;
        peer.addr6.sin6_port   = htons(atoi(argv[optind + 1]));
    }
    else
    {
        fprintf(stderr, "`%s' is not a valid IP address\n", argv[optind]);
        exit(EXIT_FAILURE);
    }

    if (cert_file || key_file)
    {
        if (!(cert_file && key_file))
        {
            fprintf(stderr, "Specify both cert (-c) and key (-k) files\n");
            exit(EXIT_FAILURE);
        }
        if (0 != tut_load_cert(cert_file, key_file))
        {
            fprintf(stderr, "Cannot load certificate\n");
            exit(EXIT_FAILURE);
        }
        tut.tut_flags |= TUT_SERVER;
    }

    /* Initialize event loop */
    tut.tut_loop = EV_DEFAULT;

    /* Set up socket */
    if (tut.tut_flags & TUT_SERVER)
    {
    }
    else
    {
        tut.tut_sock_fd = socket(peer.sa.sa_family, SOCK_DGRAM, 0);
        if (tut.tut_sock_fd < 0)
        {
            perror("socket");
            exit(EXIT_FAILURE);
        }
        tut.tut_local_sas.ss_family = peer.sa.sa_family;
        socklen = sizeof(tut.tut_local_sas);
        if (0 != bind(tut.tut_sock_fd,
                        (struct sockaddr *) &tut.tut_local_sas, socklen))
        {
            perror("bind");
            exit(EXIT_FAILURE);
        }
        if (0 != tut_set_nonblocking(tut.tut_sock_fd))
        {
            perror("fcntl");
            exit(EXIT_FAILURE);
        }
        ev_io_init(&tut.tut_sock_w, tut_read_socket, tut.tut_sock_fd, EV_READ);
        ev_io_start(tut.tut_loop, &tut.tut_sock_w);
        ev_init(&tut.tut_timer, tut_timer_expired);
    }

    /* Initialize logging */
    lsquic_logger_init(&logger_if, s_log_fh, LLTS_HHMMSSUS);

    /* Initialize callbacks */
    memset(&eapi, 0, sizeof(eapi));
    eapi.ea_packets_out = tut_packets_out;
    eapi.ea_packets_out_ctx = &tut;
    eapi.ea_stream_if   = &tut_client_callbacks;
    eapi.ea_stream_if_ctx = &tut;

    tut.tut_engine = lsquic_engine_new(tut.tut_flags & TUT_SERVER
                                            ? LSENG_SERVER : 0, &eapi);
    if (!tut.tut_engine)
    {
        fprintf(stderr, "cannot create engine\n");
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
            (struct sockaddr *) &tut.tut_local_sas, &peer.sa,
            (void *) (uintptr_t) tut.tut_sock_fd,  /* Peer ctx */
            NULL, NULL, 0, NULL, 0, NULL, 0);
        if (!tut.tut_u.c.conn)
        {
            fprintf(stderr, "cannot create connection\n");
            exit(EXIT_FAILURE);
        }
        tut_process_conns(&tut);
    }
    ev_run(tut.tut_loop, 0);

    lsquic_engine_destroy(tut.tut_engine);
    lsquic_global_cleanup();
    exit(EXIT_SUCCESS);
}
