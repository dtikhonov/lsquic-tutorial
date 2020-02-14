/* Copyright (c) 2020 LiteSpeed Technologies */
/*
 * tut.c is the example program to illustrate lsquic API usage.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lsquic.h"


static int
tut_log_buf (void *ctx, const char *buf, size_t len)
{
    FILE *out = ctx;
    fwrite(buf, 1, len, out);
    fflush(out);
    return 0;
}
static const struct lsquic_logger_if logger_if = { tut_log_buf, };


static int
tut_packets_out (void *packets_out_ctx,
    const struct lsquic_out_spec *out_spec,
    unsigned n_packets_out)
{
    /* TODO */  return -1;
}


int
main (void)
{
    struct lsquic_engine_api eapi;
    struct lsquic_engine *engine;

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER|LSQUIC_GLOBAL_CLIENT))
    {
        fprintf(stderr, "global initialization failed\n");
        exit(EXIT_FAILURE);
    }

    /* Initialize logging */
    lsquic_logger_init(&logger_if, stderr, LLTS_NONE);

    /* Initialize callbacks */
    memset(&eapi, 0, sizeof(eapi));
    eapi.ea_packets_out = tut_packets_out;

    engine = lsquic_engine_new(LSENG_SERVER, &eapi);
    if (!engine)
    {
        fprintf(stderr, "cannot create engine\n");
        exit(EXIT_FAILURE);
    }

    lsquic_engine_destroy(engine);
    lsquic_global_cleanup();
    exit(EXIT_SUCCESS);
}
