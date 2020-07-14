/* Copyright (c) 2020 LiteSpeed Technologies */
/*
 * h3cli.c is a simple HTTP/3 client.  It is used to illustrate how to use
 * lsquic HTTP/3 API.
 *
 * Example: h3cli www.litespeedtech.com 443 / -M HEAD
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#define EV_STANDALONE 1
#define EV_API_STATIC 1
#include "ev.c"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#include "lsquic.h"
#include "lsxpack_header.h"


static FILE *s_log_fh;


struct h3cli
{
    int                         h3cli_sock_fd;    /* socket */
    ev_io                       h3cli_sock_w;     /* socket watcher */
    ev_timer                    h3cli_timer;
    struct ev_loop             *h3cli_loop;
    lsquic_engine_t            *h3cli_engine;
    const char                 *h3cli_method;
    const char                 *h3cli_path;
    const char                 *h3cli_hostname;
    lsquic_conn_t              *h3cli_conn;
    struct sockaddr_storage     h3cli_local_sas;
};

static void h3cli_process_conns (struct h3cli *);

static int
h3cli_log_buf (void *ctx, const char *buf, size_t len)
{
    FILE *out = ctx;
    fwrite(buf, 1, len, out);
    fflush(out);
    return 0;
}
static const struct lsquic_logger_if logger_if = { h3cli_log_buf, };


static int s_verbose;
static void
LOG (const char *fmt, ...)
{
    if (s_verbose)
    {
        va_list ap;
        fprintf(s_log_fh, "LOG: ");
        va_start(ap, fmt);
        (void) vfprintf(s_log_fh, fmt, ap);
        va_end(ap);
        fprintf(s_log_fh, "\n");
    }
}


static int
h3cli_packets_out (void *packets_out_ctx, const struct lsquic_out_spec *specs,
                                                                unsigned count)
{
    unsigned n;
    int fd, s = 0;
    struct msghdr msg;

    if (0 == count)
        return 0;

    n = 0;
    msg.msg_flags      = 0;
    msg.msg_control    = NULL;
    msg.msg_controllen = 0;
    do
    {
        fd                 = (int) (uint64_t) specs[n].peer_ctx;
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = (AF_INET == specs[n].dest_sa->sa_family ?
                                            sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6)),
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
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
h3cli_usage (const char *argv0)
{
    const char *name;

    name = strchr(argv0, '/');
    if (name)
        ++name;
    else
        name = argv0;

    fprintf(stdout,
"Usage: %s [options] hostname port path\n"
"\n"
"   -L level        Set library-wide log level.  Defaults to 'warn'.\n"
"   -l module=level Set log level of specific module.  Several of these\n"
"                     can be specified via multiple -l flags or by combining\n"
"                     these with comma, e.g. -l event=debug,conn=info.\n"
"   -v              Verbose: log program messages as well.\n"
"   -M METHOD       Method.  GET by default.\n"
"   -o opt=val      Set lsquic engine setting to some value, overriding the\n"
"                     defaults.  For example,\n"
"                           -o version=ff00001c -o cc_algo=2\n"
"   -G DIR          Log TLS secrets to a file in directory DIR.\n"
"   -h              Print this help screen and exit.\n"
    , name);
}


static lsquic_conn_ctx_t *
h3cli_client_on_new_conn (void *stream_if_ctx, struct lsquic_conn *conn)
{
    struct h3cli *const h3cli = stream_if_ctx;
    LOG("created connection");
    lsquic_conn_make_stream(conn);
    return (void *) h3cli;
}


static void
h3cli_client_on_conn_closed (struct lsquic_conn *conn)
{
    struct h3cli *const h3cli = (void *) lsquic_conn_get_ctx(conn);

    LOG("client connection closed -- stop reading from socket");
    ev_io_stop(h3cli->h3cli_loop, &h3cli->h3cli_sock_w);
}


static lsquic_stream_ctx_t *
h3cli_client_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct h3cli *h3cli = stream_if_ctx;
    LOG("created new stream, we want to write");
    lsquic_stream_wantwrite(stream, 1);
    /* return h3cli: we don't have any stream-specific context */
    return (void *) h3cli;
}


static void
h3cli_client_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct h3cli *h3cli = (struct h3cli *) h;
    ssize_t nread;
    unsigned char buf[0x1000];

    nread = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nread > 0)
    {
        fwrite(buf, 1, nread, stdout);
        fflush(stdout);
    }
    else if (nread == 0)
    {
        LOG("read to end-of-stream: close connection");
        lsquic_stream_shutdown(stream, 0);
        lsquic_conn_close( lsquic_stream_conn(stream) );
    }
    else
    {
        LOG("error reading from stream (%s) -- exit loop");
        ev_break(h3cli->h3cli_loop, EVBREAK_ONE);
    }
}


struct header_buf
{
    unsigned    off;
    char        buf[UINT16_MAX];
};


/* Convenience wrapper around somewhat involved lsxpack APIs */
int
h3cli_set_header (struct lsxpack_header *hdr, struct header_buf *header_buf,
            const char *name, size_t name_len, const char *val, size_t val_len)
{
    if (header_buf->off + name_len + val_len <= sizeof(header_buf->buf))
    {
        memcpy(header_buf->buf + header_buf->off, name, name_len);
        memcpy(header_buf->buf + header_buf->off + name_len, val, val_len);
        lsxpack_header_set_offset2(hdr, header_buf->buf + header_buf->off,
                                            0, name_len, name_len, val_len);
        header_buf->off += name_len + val_len;
        return 0;
    }
    else
        return -1;
}


/* Send HTTP/3 request.  We don't support payload, just send the headers. */
static void
h3cli_client_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    struct h3cli *const h3cli = (void *) h;
    struct header_buf hbuf;
    struct lsxpack_header harray[5];
    struct lsquic_http_headers headers = { 5, harray, };

    hbuf.off = 0;
#define V(v) (v), strlen(v)
    h3cli_set_header(&harray[0], &hbuf, V(":method"), V(h3cli->h3cli_method));
    h3cli_set_header(&harray[1], &hbuf, V(":scheme"), V("https"));
    h3cli_set_header(&harray[2], &hbuf, V(":path"), V(h3cli->h3cli_path));
    h3cli_set_header(&harray[3], &hbuf, V(":authority"),
                                                    V(h3cli->h3cli_hostname));
    h3cli_set_header(&harray[4], &hbuf, V("user-agent"), V("h3cli/lsquic"));

    if (0 == lsquic_stream_send_headers(stream, &headers, 0))
    {
        lsquic_stream_shutdown(stream, 1);
        lsquic_stream_wantread(stream, 1);
    }
    else
    {
        LOG("ERROR: lsquic_stream_send_headers failed: %s", strerror(errno));
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}


static void
h3cli_client_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *h)
{
    LOG("stream closed");
}


static struct lsquic_stream_if h3cli_client_callbacks =
{
    .on_new_conn        = h3cli_client_on_new_conn,
    .on_conn_closed     = h3cli_client_on_conn_closed,
    .on_new_stream      = h3cli_client_on_new_stream,
    .on_read            = h3cli_client_on_read,
    .on_write           = h3cli_client_on_write,
    .on_close           = h3cli_client_on_close,
};


static int
h3cli_set_nonblocking (int fd)
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
h3cli_timer_expired (EV_P_ ev_timer *timer, int revents)
{
    h3cli_process_conns(timer->data);
}


static void
h3cli_process_conns (struct h3cli *h3cli)
{
    int diff;
    ev_tstamp timeout;

    ev_timer_stop(h3cli->h3cli_loop, &h3cli->h3cli_timer);
    lsquic_engine_process_conns(h3cli->h3cli_engine);

    if (lsquic_engine_earliest_adv_tick(h3cli->h3cli_engine, &diff))
    {
        if (diff >= LSQUIC_DF_CLOCK_GRANULARITY)
            /* Expected case: convert to seconds */
            timeout = (ev_tstamp) diff / 1000000;
        else if (diff <= 0)
            /* It should not happen often that the next tick is in the past
             * as we just processed connections.  Avoid a busy loop by
             * scheduling an event:
             */
            timeout = 0.0;
        else
            /* Round up to granularity */
            timeout = (ev_tstamp) LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
        LOG("converted diff %d usec to %.4lf seconds", diff, timeout);
        ev_timer_init(&h3cli->h3cli_timer, h3cli_timer_expired, timeout, 0.);
        ev_timer_start(h3cli->h3cli_loop, &h3cli->h3cli_timer);
    }
}


static void
h3cli_proc_ancillary (struct msghdr *msg, struct sockaddr_storage *storage,
                                                                    int *ecn)
{
    const struct in6_pktinfo *in6_pkt;
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
        if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS)
                 || (cmsg->cmsg_level == IPPROTO_IPV6
                                            && cmsg->cmsg_type == IPV6_TCLASS))
        {
            memcpy(ecn, CMSG_DATA(cmsg), sizeof(*ecn));
            *ecn &= IPTOS_ECN_MASK;
        }
    }
}


#if defined(IP_RECVORIGDSTADDR)
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#else
#   define DST_MSG_SZ sizeof(struct in_pktinfo)
#endif

#define ECN_SZ CMSG_SPACE(sizeof(int))

/* Amount of space required for incoming ancillary data */
#define CTL_SZ ECN_SZ


static void
h3cli_read_socket (EV_P_ ev_io *w, int revents)
{
    struct h3cli *const h3cli = w->data;
    ssize_t nread;
    int ecn;
    struct sockaddr_storage peer_sas, local_sas;
    unsigned char buf[0x1000];
    struct iovec vec[1] = {{ buf, sizeof(buf) }};
    unsigned char ctl_buf[CTL_SZ];

    struct msghdr msg = {
        .msg_name       = &peer_sas,
        .msg_namelen    = sizeof(peer_sas),
        .msg_iov        = vec,
        .msg_iovlen     = 1,
        .msg_control    = ctl_buf,
        .msg_controllen = sizeof(ctl_buf),
    };
    nread = recvmsg(w->fd, &msg, 0);
    if (-1 == nread) {
        if (!(EAGAIN == errno || EWOULDBLOCK == errno))
            LOG("recvmsg: %s", strerror(errno));
        return;
    }

    local_sas = h3cli->h3cli_local_sas;
    ecn = 0;
    h3cli_proc_ancillary(&msg, &local_sas, &ecn);

    (void) lsquic_engine_packet_in(h3cli->h3cli_engine, buf, nread,
        (struct sockaddr *) &local_sas,
        (struct sockaddr *) &peer_sas,
        (void *) (uintptr_t) w->fd, ecn);

    h3cli_process_conns(h3cli);
}


static void *
keylog_open (void *ctx, lsquic_conn_t *conn)
{
    const char *const dir = ctx ? ctx : ".";
    const lsquic_cid_t *cid;
    FILE *fh;
    int sz;
    unsigned i;
    char id_str[MAX_CID_LEN * 2 + 1];
    char path[PATH_MAX];
    static const char b2c[16] = "0123456789ABCDEF";

    cid = lsquic_conn_id(conn);
    for (i = 0; i < cid->len; ++i)
    {
        id_str[i * 2 + 0] = b2c[ cid->idbuf[i] >> 4 ];
        id_str[i * 2 + 1] = b2c[ cid->idbuf[i] & 0xF ];
    }
    id_str[i * 2] = '\0';
    sz = snprintf(path, sizeof(path), "%s/%s.keys", dir, id_str);
    if ((size_t) sz >= sizeof(path))
    {
        LOG("WARN: %s: file too long", __func__);
        return NULL;
    }
    fh = fopen(path, "wb");
    if (!fh)
        LOG("WARN: could not open %s for writing: %s", path, strerror(errno));
    return fh;
}


static void
keylog_log_line (void *handle, const char *line)
{
    fputs(line, handle);
    fputs("\n", handle);
    fflush(handle);
}


static void
keylog_close (void *handle)
{
    fclose(handle);
}


static const struct lsquic_keylog_if keylog_if =
{
    .kli_open       = keylog_open,
    .kli_log_line   = keylog_log_line,
    .kli_close      = keylog_close,
};


int
main (int argc, char **argv)
{
    struct lsquic_engine_api eapi;
    const char *cert_file = NULL, *key_file = NULL, *val, *port_str;
    int opt, version_cleared = 0, settings_initialized = 0;
    struct addrinfo hints, *res = NULL;
    socklen_t socklen;
    struct lsquic_engine_settings settings;
    struct h3cli h3cli;
    union {
        struct sockaddr     sa;
        struct sockaddr_in  addr4;
        struct sockaddr_in6 addr6;
    } addr;
    const char *key_log_dir = NULL;
    char errbuf[0x100];

    s_log_fh = stderr;

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT))
    {
        fprintf(stderr, "global initialization failed\n");
        exit(EXIT_FAILURE);
    }

    memset(&h3cli, 0, sizeof(h3cli));
    h3cli.h3cli_method = "GET";

    while (opt = getopt(argc, argv, "f:l:o:G:L:M:hv"), opt != -1)
    {
        switch (opt)
        {
        case 'c':
            if (settings_initialized)
            {
                fprintf(stderr, "-c and -k should precede -o flags\n");
                exit(EXIT_FAILURE);
            }
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
            if (settings_initialized)
            {
                fprintf(stderr, "-c and -k should precede -o flags\n");
                exit(EXIT_FAILURE);
            }
            key_file = optarg;
            break;
        case 'l':
            if (0 != lsquic_logger_lopt(optarg))
            {
                fprintf(stderr, "error processing -l option\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'G':
            key_log_dir = optarg;
            break;
        case 'L':
            if (0 != lsquic_set_log_level(optarg))
            {
                fprintf(stderr, "error processing -L option\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'M':
            h3cli.h3cli_method = optarg;
            break;
        case 'v':
            ++s_verbose;
            break;
        case 'o':   /* For example: -o version=h3-27 */
            if (!settings_initialized)
            {
                lsquic_engine_init_settings(&settings, LSENG_HTTP);
                settings_initialized = 1;
            }
            val = strchr(optarg, '=');
            if (!val)
            {
                fprintf(stderr, "error processing -o: no equal sign\n");
                exit(EXIT_FAILURE);
            }
            ++val;
            if (0 == strncmp(optarg, "version=", val - optarg))
            {
                if (!version_cleared)
                {
                    /* Clear all version on first -o version= */
                    version_cleared = 1;
                    settings.es_versions = 0;
                }
                enum lsquic_version ver = lsquic_str2ver(val, strlen(val));
                if ((unsigned) ver < N_LSQVER)
                {
                    settings.es_versions |= 1 << ver;
                    break;
                }
                ver = lsquic_alpn2ver(val, strlen(val));
                if ((unsigned) ver < N_LSQVER)
                {
                    settings.es_versions |= 1 << ver;
                    break;
                }
                fprintf(stderr, "error: unknown version `%s'\n", val);
                exit(EXIT_FAILURE);
            }
            else if (0 == strncmp(optarg, "cc_algo=", val - optarg))
                settings.es_cc_algo = atoi(val);
            /* ...and so on: add more options here as necessary */
            else
            {
                fprintf(stderr, "error: unknown option `%.*s'\n",
                                        (int) (val - 1 - optarg), optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'h':
            h3cli_usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        default:
            exit(EXIT_FAILURE);
            break;
        }
    }

    /* Need hostname, port, and path */
    if (optind + 2 >= argc)
    {
        LOG("please specify hostname, port, and path");
        exit(EXIT_FAILURE);
    }
    h3cli.h3cli_hostname = argv[optind];
    port_str             = argv[optind + 1];
    h3cli.h3cli_path     = argv[optind + 2];

    /* Resolve hostname */
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICSERV;
    if (0 != getaddrinfo(h3cli.h3cli_hostname, port_str, &hints, &res))
    {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }
    memcpy(&addr.sa, res->ai_addr, res->ai_addrlen);

    if (!settings_initialized)
        lsquic_engine_init_settings(&settings, LSENG_HTTP);

    /* At the time of this writing, using the loss bits extension causes
     * decryption failures in Wireshark.  For the purposes of the demo, we
     * override the default.
     */
    settings.es_ql_bits = 0;

    /* Check settings */
    if (0 != lsquic_engine_check_settings(&settings, LSENG_HTTP,
                                                    errbuf, sizeof(errbuf)))
    {
        LOG("invalid settings: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    /* Initialize event loop */
    h3cli.h3cli_loop = EV_DEFAULT;
    h3cli.h3cli_sock_fd = socket(addr.sa.sa_family, SOCK_DGRAM, 0);

    /* Set up socket */
    if (h3cli.h3cli_sock_fd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    if (0 != h3cli_set_nonblocking(h3cli.h3cli_sock_fd))
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    h3cli.h3cli_local_sas.ss_family = addr.sa.sa_family;
    socklen = sizeof(h3cli.h3cli_local_sas);
    if (0 != bind(h3cli.h3cli_sock_fd,
                    (struct sockaddr *) &h3cli.h3cli_local_sas, socklen))
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    ev_init(&h3cli.h3cli_timer, h3cli_timer_expired);
    ev_io_init(&h3cli.h3cli_sock_w, h3cli_read_socket, h3cli.h3cli_sock_fd, EV_READ);
    ev_io_start(h3cli.h3cli_loop, &h3cli.h3cli_sock_w);

    /* Initialize logging */
    setvbuf(s_log_fh, NULL, _IOLBF, 0);
    lsquic_logger_init(&logger_if, s_log_fh, LLTS_HHMMSSUS);

    /* Initialize callbacks */
    memset(&eapi, 0, sizeof(eapi));
    eapi.ea_packets_out     = h3cli_packets_out;
    eapi.ea_packets_out_ctx = &h3cli;
    eapi.ea_stream_if       = &h3cli_client_callbacks;
    eapi.ea_stream_if_ctx   = &h3cli;
    if (key_log_dir)
    {
        eapi.ea_keylog_if = &keylog_if;
        eapi.ea_keylog_ctx = (void *) key_log_dir;
    }
    eapi.ea_settings = &settings;

    h3cli.h3cli_engine = lsquic_engine_new(LSENG_HTTP, &eapi);
    if (!h3cli.h3cli_engine)
    {
        LOG("cannot create engine");
        exit(EXIT_FAILURE);
    }

    h3cli.h3cli_timer.data = &h3cli;
    h3cli.h3cli_sock_w.data = &h3cli;
    h3cli.h3cli_conn = lsquic_engine_connect(
            h3cli.h3cli_engine, N_LSQVER,
            (struct sockaddr *) &h3cli.h3cli_local_sas, &addr.sa,
            (void *) (uintptr_t) h3cli.h3cli_sock_fd,  /* Peer ctx */
            NULL, h3cli.h3cli_hostname, 0, NULL, 0, NULL, 0);
    if (!h3cli.h3cli_conn)
    {
        LOG("cannot create connection");
        exit(EXIT_FAILURE);
    }
    h3cli_process_conns(&h3cli);
    ev_run(h3cli.h3cli_loop, 0);

    lsquic_engine_destroy(h3cli.h3cli_engine);
    lsquic_global_cleanup();
    exit(EXIT_SUCCESS);
}
