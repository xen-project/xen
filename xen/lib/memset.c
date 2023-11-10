/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>

/**
 * memset - Fill a region of memory with the given value
 * @s: Pointer to the start of the area.
 * @c: The byte to fill the area with
 * @n: The size of the area.
 *
 * Do not use memset() to access IO space, use memset_io() instead.
 */
void *(memset)(void *s, int c, size_t n)
{
	char *xs = (char *) s;

	while (n--)
		*xs++ = c;

	return s;
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
