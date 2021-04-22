/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>

/**
 * memchr_inv - Find an unmatching character in an area of memory.
 * @s: The memory area
 * @c: The byte that is expected
 * @n: The size of the area.
 *
 * returns the address of the first occurrence of a character other than @c,
 * or %NULL if the whole buffer contains just @c.
 */
void *memchr_inv(const void *s, int c, size_t n)
{
	const unsigned char *p = s;

	while (n--)
		if ((unsigned char)c != *p++)
			return (void *)(p - 1);

	return NULL;
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
