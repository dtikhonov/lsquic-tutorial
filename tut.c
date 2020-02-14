#include "lsquic.h"

int
main (void)
{
    lsquic_global_init(LSQUIC_GLOBAL_SERVER|LSQUIC_GLOBAL_CLIENT);
    lsquic_global_cleanup();
    return 0;
}
