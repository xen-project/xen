
#include <linux/string.h>
#include <asm-xen/hypervisor.h>

#if 0
static __inline__ int HYPERVISOR_console_write(const char *str, int count)
{
	int ret;
	__asm__ __volatile__ (
		TRAP_INSTR
		: "=a" (ret) : "0" (__HYPERVISOR_console_write), 
		"b" (str), "c" (count) : "memory" );


	return ret;
}
#endif

#if 01
void
xen_puts(const char *str)
{

	(void)HYPERVISOR_console_io(CONSOLEIO_write, strlen(str), (char *)str);
}

asmlinkage int CLPRINTK(const char *fmt, ...)
{
	va_list args;
	int printk_len;
	static char printk_buf[1024+1];
    
	/* Emit the output into the temporary buffer */
	va_start(args, fmt);
	printk_len = vsnprintf(printk_buf, sizeof(printk_buf)-1, fmt, args);
	va_end(args);

	printk_buf[printk_len] = 0;
	/* Send the processed output directly to Xen. */
	(void)HYPERVISOR_console_io(CONSOLEIO_write, printk_len, printk_buf);

	return 0;
}
#endif
