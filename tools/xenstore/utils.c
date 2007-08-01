#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>

#include "utils.h"

void xprintf(const char *fmt, ...)
{
	static FILE *out = NULL;
	va_list args;
	if (!out)
		out = stderr;

	va_start(args, fmt);
	vfprintf(out, fmt, args);
	va_end(args);
	fflush(out);
}

void barf(const char *fmt, ...)
{
	char *str;
	int bytes;
	va_list arglist;

	xprintf("FATAL: ");

	va_start(arglist, fmt);
	bytes = vasprintf(&str, fmt, arglist);
	va_end(arglist);

 	if (bytes >= 0) {
		xprintf("%s\n", str);
		free(str);
	}
	exit(1);
}

void barf_perror(const char *fmt, ...)
{
	char *str;
	int bytes, err = errno;
	va_list arglist;

	xprintf("FATAL: ");

	va_start(arglist, fmt);
	bytes = vasprintf(&str, fmt, arglist);
	va_end(arglist);

 	if (bytes >= 0) {
		xprintf("%s: %s\n", str, strerror(err));
		free(str);
	}
	exit(1);
}
