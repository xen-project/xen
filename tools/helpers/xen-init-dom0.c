#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <xenstore.h>

#include "init-dom-json.h"

#define DOMNAME_PATH   "/local/domain/0/name"
#define DOMID_PATH     "/local/domain/0/domid"

int main(int argc, char **argv)
{
    int rc;
    struct xs_handle *xsh;
    char *domname_string = NULL, *domid_string = NULL;

    xsh = xs_open(0);
    if (!xsh) {
        fprintf(stderr, "cannot open xenstore connection\n");
        exit(1);
    }

    /* Sanity check: this program can only be run once. */
    domid_string = xs_read(xsh, XBT_NULL, DOMID_PATH, NULL);
    domname_string = xs_read(xsh, XBT_NULL, DOMNAME_PATH, NULL);
    if (domid_string && domname_string) {
        fprintf(stderr, "Dom0 is already set up\n");
        rc = 0;
        goto out;
    }

    rc = gen_stub_json_config(0);
    if (rc)
        goto out;

    /* Write xenstore entries. */
    if (!xs_write(xsh, XBT_NULL, DOMID_PATH, "0", strlen("0"))) {
        fprintf(stderr, "cannot set domid for Dom0\n");
        rc = 1;
        goto out;
    }

    if (!xs_write(xsh, XBT_NULL, DOMNAME_PATH, "Domain-0",
                  strlen("Domain-0"))) {
        fprintf(stderr, "cannot set domain name for Dom0\n");
        rc = 1;
        goto out;
    }

    printf("Done setting up Dom0\n");

out:
    free(domid_string);
    free(domname_string);
    xs_close(xsh);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
