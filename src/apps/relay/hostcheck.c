// TODO SLG - do we want a copyright block here?

#define __USE_GNU
#include "hostcheck.h"
#include <string.h>

int wildcard_hostcheck(const char *hostname, const char *match_pattern)
{
    if(!match_pattern || !*match_pattern || !hostname || !*hostname) 
        return 0;

    // TODO SLG - just do non-wildcard check for now
    if(strcmp(hostname, match_pattern) == 0)
        return 1;

    return 0;
}