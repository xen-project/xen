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
	va_list arglist;

	xprintf("FATAL: ");

	va_start(arglist, fmt);
	vasprintf(&str, fmt, arglist);
	va_end(arglist);

	xprintf("%s\n", str);
	free(str);
	exit(1);
}

void barf_perror(const char *fmt, ...)
{
	char *str;
	int err = errno;
	va_list arglist;

	xprintf("FATAL: ");

	va_start(arglist, fmt);
	vasprintf(&str, fmt, arglist);
	va_end(arglist);

	xprintf("%s: %s\n", str, strerror(err));
	free(str);
	exit(1);
}

void *_realloc_array(void *ptr, size_t size, size_t num)
{
	if (num >= SIZE_MAX/size)
		return NULL;
	return realloc_nofail(ptr, size * num);
}

void *realloc_nofail(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (ptr)
		return ptr;
	barf("realloc of %zu failed", size);
}

void *malloc_nofail(size_t size)
{
	void *ptr = malloc(size);
	if (ptr)
		return ptr;
	barf("malloc of %zu failed", size);
}

/* This version adds one byte (for nul term) */
void *grab_file(const char *filename, unsigned long *size)
{
	unsigned int max = 16384;
	int ret, fd;
	void *buffer;

	if (streq(filename, "-"))
		fd = dup(STDIN_FILENO);
	else
		fd = open(filename, O_RDONLY, 0);

	if (fd == -1)
		return NULL;

	buffer = malloc(max+1);
	if (!buffer)
		goto error;
	*size = 0;
	while ((ret = read(fd, buffer + *size, max - *size)) > 0) {
		*size += ret;
		if (*size == max) {
			void *nbuffer;
			max *= 2;
			nbuffer = realloc(buffer, max + 1);
			if (!nbuffer)
				goto error;
			buffer = nbuffer;
		}
	}
	if (ret < 0)
		goto error;
	((char *)buffer)[*size] = '\0';
	close(fd);
	return buffer;
error:
	free(buffer);
	close(fd);
	return NULL;
}

void release_file(void *data, unsigned long size __attribute__((unused)))
{
	free(data);
}
