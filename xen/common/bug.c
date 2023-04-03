#include <xen/bug.h>
/*
 * Ideally <xen/debugger.h> should be included in <asm/bug.h>
 * but an issue with compilation can occur as <xen/debugger.h> uses
 * BUG/ASSERT/etc macros inside but they will be defined later in
 * <xen/bug.h> after return from inclusion of <asm/bug.h>:
 * 
 * <xen/bug.h>:
 *  ...
 *   <asm/bug.h>:
 *     ...
 *     <xen/debugger.h> -> some of included header in it uses BUG/ASSERT/etc
 *     ...
 *  ...
 *  #define BUG() ...
 *  ...
 *  #define ASSERT() ...
 *  ...
 */
#include <xen/debugger.h>
#include <xen/errno.h>
#include <xen/kernel.h>
#include <xen/livepatch.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/virtual_region.h>

/*
 * Returns a negative value in case of an error otherwise
 * BUGFRAME_{run_fn, warn, bug, assert}
 */
int do_bug_frame(struct cpu_user_regs *regs, unsigned long pc)
{
    const struct bug_frame *bug = NULL;
    const struct virtual_region *region;
    const char *prefix = "", *filename, *predicate;
    unsigned long fixup;
    unsigned int id, lineno;

    region = find_text_region(pc);
    if ( !region )
        return -EINVAL;

    for ( id = 0; id < BUGFRAME_NR; id++ )
    {
        const struct bug_frame *b;
        size_t i;

        for ( i = 0, b = region->frame[id].bugs;
              i < region->frame[id].n_bugs; b++, i++ )
        {
            if ( bug_loc(b) == pc )
            {
                bug = b;
                goto found;
            }
        }
    }

 found:
    if ( !bug )
        return -ENOENT;

    if ( id == BUGFRAME_run_fn )
    {
        void (*fn)(struct cpu_user_regs *) = bug_ptr(bug);

        fn(regs);

        /* Re-enforce consistent types, because of the casts involved. */
        if ( false )
            run_in_exception_handler(fn);

        return id;
    }

    /* WARN, BUG or ASSERT: decode the filename pointer and line number. */
    filename = bug_ptr(bug);
    if ( !is_kernel(filename) && !is_patch(filename) )
        return -EINVAL;
    fixup = strlen(filename);
    if ( fixup > 50 )
    {
        filename += fixup - 47;
        prefix = "...";
    }
    lineno = bug_line(bug);

    switch ( id )
    {
    case BUGFRAME_warn:
        printk("Xen WARN at %s%s:%d\n", prefix, filename, lineno);
        show_execution_state(regs);

        break;

    case BUGFRAME_bug:
        printk("Xen BUG at %s%s:%d\n", prefix, filename, lineno);

        if ( BUG_DEBUGGER_TRAP_FATAL(regs) )
            break;

        show_execution_state(regs);
        panic("Xen BUG at %s%s:%d\n", prefix, filename, lineno);

    case BUGFRAME_assert:
        /* ASSERT: decode the predicate string pointer. */
        predicate = bug_msg(bug);
        if ( !is_kernel(predicate) && !is_patch(predicate) )
            predicate = "<unknown>";

        printk("Assertion '%s' failed at %s%s:%d\n",
               predicate, prefix, filename, lineno);

        if ( BUG_DEBUGGER_TRAP_FATAL(regs) )
            break;

        show_execution_state(regs);
        panic("Assertion '%s' failed at %s%s:%d\n",
              predicate, prefix, filename, lineno);
    }

    return id;
}
