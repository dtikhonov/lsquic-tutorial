/* Copyright (c) 2020 LiteSpeed Technologies */
/*
 * tut.c is the example program to illustrate lsquic API usage.
 */

#include <stdio.h>
#include <stdlib.h>

#include "lsquic.h"

int
main (void)
{
    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER|LSQUIC_GLOBAL_CLIENT))
    {
        fprintf(stderr, "global initialization failed\n");
        exit(EXIT_FAILURE);
    }

    lsquic_global_cleanup();
    exit(EXIT_SUCCESS);
}
