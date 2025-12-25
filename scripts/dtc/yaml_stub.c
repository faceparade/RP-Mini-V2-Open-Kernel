#include <stdio.h>
#include "dtc.h"

/* Fallback stub: YAML output disabled when libyaml is unavailable */
void dt_to_yaml(FILE *f, struct dt_info *dti)
{
    (void)f;
    (void)dti;
    fprintf(stderr, "dtc: YAML support not built (libyaml headers missing)\n");
}
