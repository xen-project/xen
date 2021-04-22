/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>

/**
 * strlcat - Append a %NUL terminated string into a sized buffer
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @size: size of destination buffer
 *
 * Compatible with *BSD: the result is always a valid
 * NUL-terminated string that fits in the buffer (unless,
 * of course, the buffer size is zero).
 */
size_t strlcat(char *dest, const char *src, size_t size)
{
	size_t slen = strlen(src);
	size_t dlen = strnlen(dest, size);
	char *p = dest + dlen;

	while ((p - dest) < size)
		if ((*p++ = *src++) == '\0')
			break;

	if (dlen < size)
		*(p-1) = '\0';

	return slen + dlen;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
