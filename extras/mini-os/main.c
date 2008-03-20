/*
 * POSIX-compatible main layer
 *
 * Samuel Thibault <Samuel.Thibault@eu.citrix.net>, October 2007
 */

#ifdef HAVE_LIBC
#include <os.h>
#include <sched.h>
#include <console.h>
#include <netfront.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fs.h>
#include <xenbus.h>
#include <events.h>

extern int main(int argc, char *argv[], char *envp[]);
extern void __libc_init_array(void);
extern void __libc_fini_array(void);

struct thread *main_thread;

#if 0
#include <stdio.h>
int main(int argc, char *argv[], char *envp[])
{
    printf("Hello, World!\n");
    return 1;
}
#endif

void _init(void)
{
}

void _fini(void)
{
}

static void call_main(void *p)
{
    char *args, /**path,*/ *msg, *c;
#ifdef CONFIG_QEMU
    char *domargs;
#endif
    int argc;
    char **argv;
    char *envp[] = { NULL };
    char *vm;
    int i;
    char path[128];

    /* Let other parts initialize (including console output) before maybe
     * crashing. */
    //sleep(1);

    start_networking();
    init_fs_frontend();

#ifdef CONFIG_QEMU
    if (!fs_import) {
        printk("No FS backend found, is it running?\n");
        do_exit();
    }

    /* Fetch argc, argv from XenStore */
    int domid;
    domid = xenbus_read_integer("target");
    if (domid == -1) {
        printk("Couldn't read target\n");
        do_exit();
    }

    snprintf(path, sizeof(path), "/local/domain/%d/vm", domid);
    msg = xenbus_read(XBT_NIL, path, &vm);
    if (msg) {
        printk("Couldn't read vm path\n");
        do_exit();
    }
    printk("dom vm is at %s\n", vm);

    snprintf(path, sizeof(path), "%s/image/dmargs", vm);
    free(vm);
    msg = xenbus_read(XBT_NIL, path, &domargs);

    if (msg) {
        printk("Couldn't get stubdom args: %s\n", msg);
        domargs = strdup("");
    }
#endif

    msg = xenbus_read(XBT_NIL, "vm", &vm);
    if (msg) {
        printk("Couldn't read vm path\n");
        do_exit();
    }

    printk("my vm is at %s\n", vm);
    snprintf(path, sizeof(path), "%s/image/cmdline", vm);
    free(vm);
    msg = xenbus_read(XBT_NIL, path, &args);

    if (msg) {
        printk("Couldn't get my args: %s\n", msg);
        args = strdup("");
    }

    argc = 1;

#define PARSE_ARGS(ARGS,START,END) \
    c = ARGS; \
    while (*c) { \
	if (*c != ' ') { \
	    START; \
	    while (*c && *c != ' ') \
		c++; \
	} else { \
            END; \
	    while (*c == ' ') \
		c++; \
	} \
    }

    PARSE_ARGS(args, argc++, );
#ifdef CONFIG_QEMU
    PARSE_ARGS(domargs, argc++, );
#endif

    argv = alloca((argc + 1) * sizeof(char *));
    argv[0] = "main";
    argc = 1;

    PARSE_ARGS(args, argv[argc++] = c, *c++ = 0)
#ifdef CONFIG_QEMU
    PARSE_ARGS(domargs, argv[argc++] = c, *c++ = 0)
#endif

    argv[argc] = NULL;

    for (i = 0; i < argc; i++)
	printf("\"%s\" ", argv[i]);
    printf("\n");

    __libc_init_array();
    environ = envp;
    tzset();

    exit(main(argc, argv, envp));
}

void _exit(int ret)
{
    close_all_files();
    __libc_fini_array();
    printk("main returned %d\n", ret);
    unbind_all_ports();
    if (!ret) {
	/* No problem, just shutdown.  */
        struct sched_shutdown sched_shutdown = { .reason = SHUTDOWN_poweroff };
        HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
    }
    do_exit();
}

int app_main(start_info_t *si)
{
    printk("Dummy main: start_info=%p\n", si);
    main_thread = create_thread("main", call_main, si);
    return 0;
}
#endif
