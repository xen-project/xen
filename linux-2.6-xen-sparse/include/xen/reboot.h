#define SHUTDOWN_INVALID  -1
#define SHUTDOWN_POWEROFF  0
#define SHUTDOWN_SUSPEND   2
/* Code 3 is SHUTDOWN_CRASH, which we don't use because the domain can only
 * report a crash, not be instructed to crash!
 * HALT is the same as POWEROFF, as far as we're concerned.  The tools use
 * the distinction when we return the reason code to them.
 */
#define SHUTDOWN_HALT      4

/******************************************************************************
 * Stop/pickle callback handling.
 */

/* Ignore multiple shutdown requests. */
static int shutting_down = SHUTDOWN_INVALID;

int kthread_create_on_cpu(int (*f)(void *), void *, const char *, int);
int __do_suspend(void *);
