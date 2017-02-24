#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xenstore.h"


int main(int argc, char **argv)
{
    struct xs_handle *xsh;
    char *par = NULL;
    char *ret;
    unsigned int p, len = 0;
    int rc = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage:\n"
                "%s <command> [<arg>...]\n", argv[0]);
        rc = 2;
        goto out;
    }

    for (p = 2; p < argc; p++)
        len += strlen(argv[p]) + 1;
    if (len) {
        par = malloc(len);
        if (!par) {
            fprintf(stderr, "Allocation error.\n");
            rc = 1;
            goto out;
        }
        len = 0;
        for (p = 2; p < argc; p++) {
            memcpy(par + len, argv[p], strlen(argv[p]) + 1);
            len += strlen(argv[p]) + 1;
        }
    }

    xsh = xs_open(0);
    if (xsh == NULL) {
        fprintf(stderr, "Failed to contact Xenstored.\n");
        rc = 1;
        goto out;
    }

    ret = xs_control_command(xsh, argv[1], par, len);
    if (!ret) {
        rc = 3;
        if (errno == EINVAL) {
            ret = xs_control_command(xsh, "help", NULL, 0);
            if (ret)
                fprintf(stderr, "Command not supported. Valid commands are:\n"
                                "%s\n", ret);
            else
                fprintf(stderr, "Error when executing command.\n");
        } else
            fprintf(stderr, "Error %d when trying to execute command.\n",
                    errno);
    } else if (strlen(ret) > 0)
        printf("%s\n", ret);

    xs_close(xsh);

 out:
    free(par);
    return rc;
}
