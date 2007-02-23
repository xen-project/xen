#ifndef OPROFILE_PERFMON_H
#define OPROFILE_PERFMON_H

#ifdef CONFIG_PERFMON
int __perfmon_init(void);
void __perfmon_exit(void);
int perfmon_start(void);
void perfmon_stop(void);
#else
#define __perfmon_init()	(-ENOSYS)
#define __perfmon_exit()	do {} while (0)
#endif /* CONFIG_PERFMON */

#ifdef CONFIG_XEN
#define STATIC_IF_NO_XEN	/* nothing */
#define xen_perfmon_init()	__perfmon_init()
#define xen_perfmon_exit()	__perfmon_exit()
extern int xenoprofile_init(struct oprofile_operations * ops);
extern void xenoprofile_exit(void);
#else
#define STATIC_IF_NO_XEN	static
#define xen_perfmon_init()	(-ENOSYS)
#define xen_perfmon_exit()	do {} while (0)
#define xenoprofile_init()	(-ENOSYS)
#define xenoprofile_exit()	do {} while (0)
#endif /* CONFIG_XEN */

#endif /* OPROFILE_PERFMON_H */
