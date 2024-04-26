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
#include <xen-tools/common-macros.h>

static xc_interface *xch;

/* Global option to disable checks. */
static bool force;

void show_help(void)
{
    fprintf(stderr,
            "xen-livepatch: live patching tool\n"
            "Usage: xen-livepatch [--force] <command> [args] [command-flags]\n"
            " Use --force option to bypass some checks.\n"
            " <name> An unique name of payload. Up to %d characters.\n"
            "Commands:\n"
            "  help                   display this help\n"
            "  upload <name> <file>   upload file <file> with <name> name\n"
            "  list                   list payloads uploaded.\n"
            "  apply <name> [flags]   apply <name> patch.\n"
            "    Supported flags:\n"
            "      --nodeps           Disable inter-module buildid dependency check.\n"
            "                         Check only against hypervisor buildid.\n"
            "  revert <name>          revert name <name> patch.\n"
            "  replace <name>         apply <name> patch and revert all others.\n"
            "  unload <name>          unload name <name> patch.\n"
            "  load <file> [flags]    upload and apply <file> with name as the <file> name\n"
            "    Supported flags:\n"
            "      --nodeps           Disable inter-module buildid dependency check.\n"
            "                         Check only against hypervisor buildid.\n",
            XEN_LIVEPATCH_NAME_SIZE);
}

/* wrapper function */
static int help_func(int argc, char *argv[])
{
    show_help();
    return 0;
}

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

static int list_func(int argc, char *argv[])
{
    unsigned int nr, done, left, i;
    xen_livepatch_status_t *info = NULL;
    char *name = NULL;
    char *metadata = NULL;
    uint32_t *len = NULL;
    uint32_t *metadata_len = NULL;
    uint32_t name_total_size, metadata_total_size, name_off, metadata_off;
    int rc = ENOMEM;

    if ( argc )
    {
        show_help();
        return -1;
    }
    done = left = 0;

    rc = xc_livepatch_list_get_sizes(xch, &nr, &name_total_size, &metadata_total_size);
    if ( rc )
    {
        rc = errno;
        fprintf(stderr, "Failed to get list sizes.\n"
                "Error %d: %s\n",
                rc, strerror(rc));
        return rc;
    }

    if ( nr == 0 )
    {
        fprintf(stdout, "Nothing to list\n");
        return 0;
    }

    info = malloc(nr * sizeof(*info));
    if ( !info )
        return rc;

    name = malloc(name_total_size * sizeof(*name));
    if ( !name )
        goto error_name;

    len = malloc(nr * sizeof(*len));
    if ( !len )
        goto error_len;

    metadata = malloc(metadata_total_size * sizeof(*metadata) + 1);
    if ( !metadata )
        goto error_metadata;

    metadata_len = malloc(nr * sizeof(*metadata_len));
    if ( !metadata_len )
        goto error_metadata_len;

    memset(info, 'A', nr * sizeof(*info));
    memset(name, 'B', name_total_size * sizeof(*name));
    memset(len, 'C', nr * sizeof(*len));
    memset(metadata, 'D', metadata_total_size * sizeof(*metadata) + 1);
    memset(metadata_len, 'E', nr * sizeof(*metadata_len));
    name_off = metadata_off = 0;

    rc = xc_livepatch_list(xch, nr, 0, info, name, len, name_total_size,
                           metadata, metadata_len, metadata_total_size, &done, &left);
    if ( rc || done != nr || left > 0)
    {
        rc = errno;
        fprintf(stderr, "Failed to list %d/%d.\n"
                "Error %d: %s\n",
                left, nr, rc, strerror(rc));
        goto error;
    }

    fprintf(stdout," ID                                     | status     | metadata\n"
                   "----------------------------------------+------------+---------------\n");

    for ( i = 0; i < done; i++ )
    {
        unsigned int j;
        char *name_str = name + name_off;
        char *metadata_str = metadata + metadata_off;

        printf("%-40.*s| %s", len[i], name_str, state2str(info[i].state));
        if ( info[i].rc )
            printf(" (%d, %s)    | ", -info[i].rc, strerror(-info[i].rc));
        else
            printf("    | ");

        /* Replace all '\0' with semi-colons. */
        for ( j = 0; metadata_len[i] && j < metadata_len[i] - 1; j++ )
            metadata_str[j] = (metadata_str[j] ?: ';');
        printf("%.*s\n", metadata_len[i], metadata_str);

        name_off += len[i];
        metadata_off += metadata_len[i];
    }

error:
    free(metadata_len);
error_metadata_len:
    free(metadata);
error_metadata:
    free(len);
error_len:
    free(name);
error_name:
    free(info);
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
    rc = xc_livepatch_upload(xch, name, fbuf, len, force);
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

/* These MUST match to the 'action_options[]' and 'flag_options[]' array slots. */
enum {
    ACTION_APPLY = 0,
    ACTION_REVERT = 1,
    ACTION_UNLOAD = 2,
    ACTION_REPLACE = 3,
    ACTION_NUM
};

struct {
    int allow; /* State it must be in to call function. */
    int expected; /* The state to be in after the function. */
    const char *name;
    const char *verb;
    int (*function)(xc_interface *xch, char *name, uint32_t timeout, uint32_t flags);
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

/*
 * This structure defines supported flag options for actions.
 * It defines entries for each action and supports up to 32
 * flags per action.
 */
struct {
    const char *name;
    const uint32_t flag;
} flag_options[ACTION_NUM][8 * sizeof(uint32_t)] = {
    { /* ACTION_APPLY */
        {   .name = "--nodeps",
            .flag = LIVEPATCH_ACTION_APPLY_NODEPS,
        },
    },
    { /* ACTION_REVERT */
    },
    { /* ACTION_UNLOAD */
    },
    { /* ACTION_REPLACE */
    }
};

/*
 * Parse user provided action flags.
 * This function expects to only receive an array of input parameters being flags.
 * Expected action is specified via idx paramater (index of flag_options[]).
 */
static int get_flags(int argc, char *argv[], unsigned int idx, uint32_t *flags)
{
    int i, j;

    if ( !flags || idx >= ARRAY_SIZE(flag_options) )
        return -1;

    *flags = 0;
    for ( i = 0; i < argc; i++ )
    {
        for ( j = 0; j < ARRAY_SIZE(flag_options[idx]); j++ )
        {
            if ( !flag_options[idx][j].name )
                goto error;

            if ( !strcmp(flag_options[idx][j].name, argv[i]) )
            {
                *flags |= flag_options[idx][j].flag;
                break;
            }
        }

        if ( j == ARRAY_SIZE(flag_options[idx]) )
            goto error;
    }

    return 0;
error:
    fprintf(stderr, "Unsupported flag: %s.\n", argv[i]);
    errno = EINVAL;
    return errno;
}

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
    uint32_t flags;

    if ( argc < 1 )
    {
        show_help();
        return -1;
    }

    if ( idx >= ARRAY_SIZE(action_options) )
        return -1;

    if ( get_name(argc--, argv++, name) )
        return EINVAL;

    if ( get_flags(argc, argv, idx, &flags) )
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
        rc = action_options[idx].function(xch, name, HYPERVISOR_TIMEOUT_NS, flags);
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
    int i, rc = ENOMEM;
    char *upload_argv[2];
    char **apply_argv, *path, *name, *lastdot;

    if ( argc < 1 )
    {
        show_help();
        return -1;
    }

    /* apply action has <id> [flags] input requirement, which must be constructed */
    apply_argv = (char **) malloc(argc * sizeof(*apply_argv));
    if ( !apply_argv )
        return rc;

    /* <file> */
    upload_argv[1] = argv[0];

    /* Synthesize the <id> */
    path = strdup(argv[0]);

    name = basename(path);
    lastdot = strrchr(name, '.');
    if ( lastdot != NULL )
        *lastdot = '\0';
    upload_argv[0] = name;
    apply_argv[0] = name;

    /* Fill in all user provided flags */
    for ( i = 1; i < argc; i++ )
        apply_argv[i] = argv[i];

    rc = upload_func(2 /* <id> <file> */, upload_argv);
    if ( rc )
        goto error;

    rc = action_func(argc, apply_argv, ACTION_APPLY);
    if ( rc )
        action_func(1 /* only <id> */, upload_argv, ACTION_UNLOAD);

error:
    free(apply_argv);
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

    if ( !strcmp("--force", argv[1]) )
    {
        if ( argc <= 2 )
        {
            show_help();
            return EXIT_FAILURE;
        }
        force = true;
        argv++;
        argc--;
    }

    for ( i = 0; i < ARRAY_SIZE(main_options); i++ )
        if (!strcmp(main_options[i].name, argv[1]))
            break;

    if ( i == ARRAY_SIZE(main_options) )
    {
        for ( j = 0; j < ARRAY_SIZE(action_options); j++ )
            if (!strcmp(action_options[j].name, argv[1]))
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
