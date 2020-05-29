#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xenhypfs.h>

static struct xenhypfs_handle *hdl;

static int usage(void)
{
    fprintf(stderr, "usage: xenhypfs ls <path>\n");
    fprintf(stderr, "       xenhypfs cat [-b] <path>\n");
    fprintf(stderr, "       xenhypfs write <path> <val>\n");
    fprintf(stderr, "       xenhypfs tree\n");

    return 1;
}

static void xenhypfs_print_escaped(char *string)
{
    char *c;

    for (c = string; *c; c++) {
        if (isgraph(*c) || isspace(*c))
            printf("%c", *c);
        else
            printf("\\x%02x", *c);
    }
    printf("\n");
}

static int xenhypfs_cat(int argc, char *argv[])
{
    int ret = 0;
    char *result;
    char *path;
    bool bin = false;

    switch (argc) {
    case 1:
        path = argv[0];
        break;

    case 2:
        if (strcmp(argv[0], "-b"))
            return usage();
        bin = true;
        path = argv[1];
        break;

    default:
        return usage();
    }

    result = xenhypfs_read(hdl, path);
    if (!result) {
        perror("could not read");
        ret = 3;
    } else {
        if (!bin)
            printf("%s\n", result);
        else
            xenhypfs_print_escaped(result);
        free(result);
    }

    return ret;
}

static int xenhypfs_wr(char *path, char *val)
{
    int ret;

    ret = xenhypfs_write(hdl, path, val);
    if (ret) {
        perror("could not write");
        ret = 3;
    }

    return ret;
}

static char *xenhypfs_type(struct xenhypfs_dirent *ent)
{
    char *res;

    switch (ent->type) {
    case xenhypfs_type_dir:
        res = "<dir>   ";
        break;
    case xenhypfs_type_blob:
        res = "<blob>  ";
        break;
    case xenhypfs_type_string:
        res = "<string>";
        break;
    case xenhypfs_type_uint:
        res = "<uint>  ";
        break;
    case xenhypfs_type_int:
        res = "<int>   ";
        break;
    case xenhypfs_type_bool:
        res = "<bool>  ";
        break;
    default:
        res = "<\?\?\?>   ";
        break;
    }

    return res;
}

static int xenhypfs_ls(char *path)
{
    struct xenhypfs_dirent *ent;
    unsigned int n, i;
    int ret = 0;

    ent = xenhypfs_readdir(hdl, path, &n);
    if (!ent) {
        perror("could not read dir");
        ret = 3;
    } else {
        for (i = 0; i < n; i++)
            printf("%s r%c %s\n", xenhypfs_type(ent + i),
                   ent[i].is_writable ? 'w' : '-', ent[i].name);

        free(ent);
    }

    return ret;
}

static int xenhypfs_tree_sub(char *path, unsigned int depth)
{
    struct xenhypfs_dirent *ent;
    unsigned int n, i;
    int ret = 0;
    char *p;

    ent = xenhypfs_readdir(hdl, path, &n);
    if (!ent)
        return 2;

    for (i = 0; i < n; i++) {
        printf("%*s%s%s\n", depth * 2, "", ent[i].name,
               ent[i].type == xenhypfs_type_dir ? "/" : "");
        if (ent[i].type == xenhypfs_type_dir) {
            asprintf(&p, "%s%s%s", path, (depth == 1) ? "" : "/", ent[i].name);
            if (xenhypfs_tree_sub(p, depth + 1))
                ret = 2;
        }
    }

    free(ent);

    return ret;
}

static int xenhypfs_tree(void)
{
    printf("/\n");

    return xenhypfs_tree_sub("/", 1);
}

int main(int argc, char *argv[])
{
    int ret;

    hdl = xenhypfs_open(NULL, 0);

    if (!hdl) {
        fprintf(stderr, "Could not open libxenhypfs\n");
        ret = 2;
    } else if (argc >= 3 && !strcmp(argv[1], "cat"))
        ret = xenhypfs_cat(argc - 2, argv + 2);
    else if (argc == 3 && !strcmp(argv[1], "ls"))
        ret = xenhypfs_ls(argv[2]);
    else if (argc == 4 && !strcmp(argv[1], "write"))
        ret = xenhypfs_wr(argv[2], argv[3]);
    else if (argc == 2 && !strcmp(argv[1], "tree"))
        ret = xenhypfs_tree();
    else
        ret = usage();

    xenhypfs_close(hdl);

    return ret;
}
