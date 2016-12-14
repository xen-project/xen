/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <xenctrl.h>
#include <xenstore.h>

#include <xen/errno.h>
#include <xen-tools/libs.h>

static xc_interface *xch;

void show_help(void)
{
    fprintf(stderr,
            "xen-livepatch: live patching tool\n"
            "Usage: xen-livepatch <command> [args]\n"
            " <name> An unique name of payload. Up to %d characters.\n"
            "Commands:\n"
            "  help                   display this help\n"
            "  upload <name> <file>   upload file <file> with <name> name\n"
            "  list                   list payloads uploaded.\n"
            "  apply <name>           apply <name> patch.\n"
            "  revert <name>          revert name <name> patch.\n"
            "  replace <name>         apply <name> patch and revert all others.\n"
            "  unload <name>          unload name <name> patch.\n"
            "  load  <file>           upload and apply <file>.\n"
            "                         name is the <file> name\n",
            XEN_LIVEPATCH_NAME_SIZE);
}

/* wrapper function */
static int help_func(int argc, char *argv[])
{
    show_help();
    return 0;
}

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

static const char *state2str(unsigned int state)
{
#define STATE(x) [LIVEPATCH_STATE_##x] = #x
    static const char *const names[] = {
            STATE(CHECKED),
            STATE(APPLIED),
    };
#undef STATE
    if (state >= ARRAY_SIZE(names) || !names[state])
        return "unknown";

    return names[state];
}

/* This value was choosen adhoc. It could be 42 too. */
#define MAX_LEN 11
static int list_func(int argc, char *argv[])
{
    unsigned int idx, done, left, i;
    xen_livepatch_status_t *info = NULL;
    char *name = NULL;
    uint32_t *len = NULL;
    int rc = ENOMEM;

    if ( argc )
    {
        show_help();
        return -1;
    }
    idx = left = 0;
    info = malloc(sizeof(*info) * MAX_LEN);
    if ( !info )
        return rc;
    name = malloc(sizeof(*name) * XEN_LIVEPATCH_NAME_SIZE * MAX_LEN);
    if ( !name )
    {
        free(info);
        return rc;
    }
    len = malloc(sizeof(*len) * MAX_LEN);
    if ( !len ) {
        free(name);
        free(info);
        return rc;
    }

    do {
        done = 0;
        /* The memset is done to catch errors. */
        memset(info, 'A', sizeof(*info) * MAX_LEN);
        memset(name, 'B', sizeof(*name) * MAX_LEN * XEN_LIVEPATCH_NAME_SIZE);
        memset(len, 'C', sizeof(*len) * MAX_LEN);
        rc = xc_livepatch_list(xch, MAX_LEN, idx, info, name, len, &done, &left);
        if ( rc )
        {
            rc = errno;
            fprintf(stderr, "Failed to list %d/%d.\n"
                            "Error %d: %s\n",
                    idx, left, rc, strerror(rc));
            break;
        }
        if ( !idx )
            fprintf(stdout," ID                                     | status\n"
                           "----------------------------------------+------------\n");

        for ( i = 0; i < done; i++ )
        {
            unsigned int j;
            uint32_t sz;
            char *str;

            sz = len[i];
            str = name + (i * XEN_LIVEPATCH_NAME_SIZE);
            for ( j = sz; j < XEN_LIVEPATCH_NAME_SIZE; j++ )
                str[j] = '\0';

            printf("%-40s| %s", str, state2str(info[i].state));
            if ( info[i].rc )
                printf(" (%d, %s)\n", -info[i].rc, strerror(-info[i].rc));
            else
                puts("");
        }
        idx += done;
    } while ( left );

    free(name);
    free(info);
    free(len);
    return rc;
}
#undef MAX_LEN

static int get_name(int argc, char *argv[], char *name)
{
    ssize_t len = strlen(argv[0]);
    if ( len > XEN_LIVEPATCH_NAME_SIZE )
    {
        fprintf(stderr, "ID must be no more than %d characters.\n",
                XEN_LIVEPATCH_NAME_SIZE);
        errno = EINVAL;
        return errno;
    }
    /* Don't want any funny strings from the stack. */
    memset(name, 0, XEN_LIVEPATCH_NAME_SIZE);
    strncpy(name, argv[0], len);
    return 0;
}

static int upload_func(int argc, char *argv[])
{
    char *filename;
    char name[XEN_LIVEPATCH_NAME_SIZE];
    int fd = 0, rc;
    struct stat buf;
    unsigned char *fbuf;
    ssize_t len;

    if ( argc != 2 )
    {
        show_help();
        return -1;
    }

    if ( get_name(argc, argv, name) )
        return EINVAL;

    filename = argv[1];
    fd = open(filename, O_RDONLY);
    if ( fd < 0 )
    {
        int saved_errno = errno;
        fprintf(stderr, "Could not open %s.\n"
                        "Error %d: %s\n",
                filename, saved_errno, strerror(saved_errno));
        return saved_errno;
    }
    if ( stat(filename, &buf) != 0 )
    {
        int saved_errno = errno;
        fprintf(stderr, "Could not get size of %s.\n"
                        "Error %d: %s\n",
                filename, saved_errno, strerror(saved_errno));
        close(fd);
        return saved_errno;
    }

    len = buf.st_size;
    fbuf = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( fbuf == MAP_FAILED )
    {
        int saved_errno = errno;
        fprintf(stderr, "Could not map %s.\n"
                        "Error %d: %s\n",
                filename, saved_errno, strerror(saved_errno));
        close (fd);
        return saved_errno;
    }
    printf("Uploading %s... ", filename);
    rc = xc_livepatch_upload(xch, name, fbuf, len);
    if ( rc )
    {
        rc = errno;
        printf("failed\n");
        fprintf(stderr, "Error %d: %s\n", rc, strerror(rc));
    }
    else
        printf("completed\n");


    if ( munmap( fbuf, len) )
    {
        fprintf(stderr, "Could not unmap %s.\n"
                        "Error %d: %s\n",
                filename, errno, strerror(errno));
    }
    close(fd);

    return rc;
}

/* These MUST match to the 'action_options[]' array slots. */
enum {
    ACTION_APPLY = 0,
    ACTION_REVERT = 1,
    ACTION_UNLOAD = 2,
    ACTION_REPLACE = 3,
};

struct {
    int allow; /* State it must be in to call function. */
    int expected; /* The state to be in after the function. */
    const char *name;
    const char *verb;
    int (*function)(xc_interface *xch, char *name, uint32_t timeout);
} action_options[] = {
    {   .allow = LIVEPATCH_STATE_CHECKED,
        .expected = LIVEPATCH_STATE_APPLIED,
        .name = "apply",
        .verb = "Applying",
        .function = xc_livepatch_apply,
    },
    {   .allow = LIVEPATCH_STATE_APPLIED,
        .expected = LIVEPATCH_STATE_CHECKED,
        .name = "revert",
        .verb = "Reverting",
        .function = xc_livepatch_revert,
    },
    {   .allow = LIVEPATCH_STATE_CHECKED,
        .expected = -XEN_ENOENT,
        .name = "unload",
        .verb = "Unloading",
        .function = xc_livepatch_unload,
    },
    {   .allow = LIVEPATCH_STATE_CHECKED,
        .expected = LIVEPATCH_STATE_APPLIED,
        .name = "replace",
        .verb = "Replacing all live patches with",
        .function = xc_livepatch_replace,
    },
};

/* The hypervisor timeout for the live patching operation is 30 msec,
 * but it could take some time for the operation to start, so wait twice
 * that period. */
#define HYPERVISOR_TIMEOUT_NS 30000000
#define DELAY (2 * HYPERVISOR_TIMEOUT_NS)

static void nanosleep_retry(long ns)
{
    struct timespec req, rem;
    int rc;

    rem.tv_sec = 0;
    rem.tv_nsec = ns;

    do {
        req = rem;
        rc = nanosleep(&req, &rem);
    } while ( rc == -1 && errno == EINTR );
}

int action_func(int argc, char *argv[], unsigned int idx)
{
    char name[XEN_LIVEPATCH_NAME_SIZE];
    int rc;
    xen_livepatch_status_t status;

    if ( argc != 1 )
    {
        show_help();
        return -1;
    }

    if ( idx >= ARRAY_SIZE(action_options) )
        return -1;

    if ( get_name(argc, argv, name) )
        return EINVAL;

    /* Check initial status. */
    rc = xc_livepatch_get(xch, name, &status);
    if ( rc )
    {
        int saved_errno = errno;
        fprintf(stderr, "Failed to get status of %s.\n"
                        "Error %d: %s\n",
                name, saved_errno, strerror(saved_errno));
        return saved_errno;
    }
    if ( status.rc == -XEN_EAGAIN )
    {
        fprintf(stderr,
                "Cannot execute %s.\n"
                "Operation already in progress.\n", action_options[idx].name);
        return EAGAIN;
    }

    if ( status.state == action_options[idx].expected )
    {
        printf("No action needed.\n");
        return 0;
    }

    /* Perform action. */
    if ( action_options[idx].allow & status.state )
    {
        printf("%s %s... ", action_options[idx].verb, name);
        rc = action_options[idx].function(xch, name, HYPERVISOR_TIMEOUT_NS);
        if ( rc )
        {
            int saved_errno = errno;
            printf("failed\n");
            fprintf(stderr, "Error %d: %s\n",
                    saved_errno, strerror(saved_errno));
            return saved_errno;
        }
    }
    else
    {
        fprintf(stderr, "%s is in the wrong state.\n"
                        "Current state: %s\n"
                        "Expected state: %s\n",
                name, state2str(status.state),
                state2str(action_options[idx].allow));
        return -1;
    }

    nanosleep_retry(DELAY);
    rc = xc_livepatch_get(xch, name, &status);

    if ( rc )
        rc = -errno;
    else if ( status.rc )
        rc = status.rc;

    if ( rc == -XEN_EAGAIN )
    {
        printf("failed\n");
        fprintf(stderr, "Operation didn't complete.\n");
        return EAGAIN;
    }

    if ( rc == 0 )
        rc = status.state;

    if ( action_options[idx].expected == rc )
        printf("completed\n");
    else if ( rc < 0 )
    {
        printf("failed\n");
        fprintf(stderr, "Error %d: %s\n", -rc, strerror(-rc));
        return -rc;
    }
    else
    {
        printf("failed\n");
        fprintf(stderr, "%s is in the wrong state.\n"
                        "Current state: %s\n"
                        "Expected state: %s\n",
                name, state2str(rc),
                state2str(action_options[idx].expected));
        return -1;
    }

    return 0;
}

static int load_func(int argc, char *argv[])
{
    int rc;
    char *new_argv[2];
    char *path, *name, *lastdot;

    if ( argc != 1 )
    {
        show_help();
        return -1;
    }
    /* <file> */
    new_argv[1] = argv[0];

    /* Synthesize the <id> */
    path = strdup(argv[0]);

    name = basename(path);
    lastdot = strrchr(name, '.');
    if ( lastdot != NULL )
        *lastdot = '\0';
    new_argv[0] = name;

    rc = upload_func(2 /* <id> <file> */, new_argv);
    if ( rc )
        return rc;

    rc = action_func(1 /* only <id> */, new_argv, ACTION_APPLY);
    if ( rc )
        action_func(1, new_argv, ACTION_UNLOAD);

    free(path);
    return rc;
}

/*
 * These are also functions in action_options that are called in case
 * none of the ones in main_options match.
 */
struct {
    const char *name;
    int (*function)(int argc, char *argv[]);
} main_options[] = {
    { "help", help_func },
    { "list", list_func },
    { "upload", upload_func },
    { "load", load_func },
};

int main(int argc, char *argv[])
{
    int i, j = 0, ret;

    /*
     * Set stdout to be unbuffered to avoid having to fflush when
     * printing without a newline.
     */
    setvbuf(stdout, NULL, _IONBF, 0);

    if ( argc  <= 1 )
    {
        show_help();
        return 0;
    }
    for ( i = 0; i < ARRAY_SIZE(main_options); i++ )
        if (!strncmp(main_options[i].name, argv[1], strlen(argv[1])))
            break;

    if ( i == ARRAY_SIZE(main_options) )
    {
        for ( j = 0; j < ARRAY_SIZE(action_options); j++ )
            if (!strncmp(action_options[j].name, argv[1], strlen(argv[1])))
                break;

        if ( j == ARRAY_SIZE(action_options) )
        {
            fprintf(stderr, "Unrecognised command '%s' -- try "
                   "'xen-livepatch help'\n", argv[1]);
            return 1;
        }
    }

    xch = xc_interface_open(0,0,0);
    if ( !xch )
    {
        fprintf(stderr, "failed to get the handler\n");
        return 0;
    }

    if ( i == ARRAY_SIZE(main_options) )
        ret = action_func(argc -2, argv + 2, j);
    else
        ret = main_options[i].function(argc -2, argv + 2);

    xc_interface_close(xch);

    /*
     * Exitcode 0 for success.
     * Exitcode 1 for an error.
     * Exitcode 2 if the operation should be retried for any reason (e.g. a
     * timeout or because another operation was in progress).
     */
#define EXIT_TIMEOUT (EXIT_FAILURE + 1)

    BUILD_BUG_ON(EXIT_SUCCESS != 0);
    BUILD_BUG_ON(EXIT_FAILURE != 1);
    BUILD_BUG_ON(EXIT_TIMEOUT != 2);

    switch ( ret )
    {
    case 0:
        return EXIT_SUCCESS;
    case EAGAIN:
    case EBUSY:
        return EXIT_TIMEOUT;
    default:
        return EXIT_FAILURE;
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
