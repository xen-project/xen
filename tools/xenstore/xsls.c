#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <xs.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>

static int max_width = 80;
static int desired_width = 60;

#define TAG " = \"...\""
#define TAG_LEN strlen(TAG)

#define MIN(a, b) (((a) < (b))? (a) : (b))

void print_dir(struct xs_handle *h, char *path, int cur_depth, int show_perms)
{
    char **e;
    char newpath[512], *val;
    int i;
    unsigned int num, len;

    e = xs_directory(h, XBT_NULL, path, &num);
    if (e == NULL)
        err(1, "xs_directory (%s)", path);

    for (i = 0; i<num; i++) {
        char buf[MAX_STRLEN(unsigned int)+1];
        struct xs_permissions *perms;
        unsigned int nperms;
        int linewid;

        for (linewid=0; linewid<cur_depth; linewid++) putchar(' ');
        linewid += printf("%.*s",
                          (int) (max_width - TAG_LEN - linewid), e[i]);
        sprintf(newpath, "%s%s%s", path, 
                path[strlen(path)-1] == '/' ? "" : "/", 
                e[i]);
        val = xs_read(h, XBT_NULL, newpath, &len);
        if (val == NULL) {
            printf(":\n");
        }
        else {
            if (max_width < (linewid + len + TAG_LEN)) {
                printf(" = \"%.*s...\"",
                       (int)(max_width - TAG_LEN - linewid), val);
            }
            else {
                linewid += printf(" = \"%s\"", val);
                if (show_perms) {
                    putchar(' ');
                    for (linewid++;
                         linewid < MIN(desired_width, max_width);
                         linewid++)
                        putchar((linewid & 1)? '.' : ' ');
                }
            }
        }
        free(val);

        if (show_perms) {
            perms = xs_get_permissions(h, XBT_NULL, newpath, &nperms);
            if (perms == NULL) {
                warn("\ncould not access permissions for %s", e[i]);
            }
            else {
                int i;
                fputs("  (", stdout);
                for (i = 0; i < nperms; i++) {
                    if (i)
                        putchar(',');
                    xs_perm_to_string(perms+i, buf);
                    fputs(buf, stdout);
                }
                putchar(')');
            }
        }

        putchar('\n');
            
        print_dir(h, newpath, cur_depth+1, show_perms); 
    }
    free(e);
}

void usage(int argc, char *argv[])
{
    fprintf(stderr, "Usage: %s [-p] [path]\n", argv[0]);
}

int main(int argc, char *argv[])
{
    struct winsize ws;
    int ret, c, socket = 0, show_perm = 0;
    struct xs_handle *xsh;

#define PAD 2

    memset(&ws, 0, sizeof(ws));
    ret = ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
    if (!ret)
        max_width = ws.ws_col - PAD;

    while (0 < (c = getopt(argc, argv, "ps"))) {
        switch (c) {
        case 'p':
            show_perm = 1;
            max_width -= 16;
            break;
        case 's':
            socket = 1;
            break;
        case ':':
        case '?':
        default:
            usage(argc, argv);
            return 0;
        }
    }

    xsh = socket ? xs_daemon_open() : xs_domain_open();
    if (xsh == NULL)
        err(1, socket ? "xs_daemon_open" : "xs_domain_open");

    print_dir(xsh, (argc - optind) == 1 ? argv[optind] : "/", 0, show_perm);

    return 0;
}
