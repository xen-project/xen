#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <xs.h>

void print_dir(struct xs_handle *h, char *path, int cur_depth)
{
    char **e;
    char newpath[512], *val;
    int i;
    unsigned int num, len;

    e = xs_directory(h, XBT_NULL, path, &num);
    if (e == NULL)
        err(1, "xs_directory (%s)", path);

    for (i = 0; i<num; i++) {
        int j;
        for (j=0; j<cur_depth; j++) printf(" ");
        printf("%s", e[i]);
        sprintf(newpath, "%s%s%s", path, 
                path[strlen(path)-1] == '/' ? "" : "/", 
                e[i]);
        val = xs_read(h, XBT_NULL, newpath, &len);
        if (val == NULL)
            printf(":\n");
        else if ((unsigned)len > (151 - strlen(e[i])))
            printf(" = \"%.*s...\"\n", (int)(148 - strlen(e[i])), val);
        else
            printf(" = \"%s\"\n", val);
        free(val);
        print_dir(h, newpath, cur_depth+1); 
    }
    free(e);
}

int main(int argc, char *argv[])
{
    struct xs_handle *xsh = xs_daemon_open();

    if (xsh == NULL)
        err(1, "xs_daemon_open");

    print_dir(xsh, argc == 1 ? "/" : argv[1], 0);

    return 0;
}
