/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>

/**
 * strstr - Find the first substring in a %NUL terminated string
 * @s1: The string to be searched
 * @s2: The string to search for
 */
char *(strstr)(const char *s1, const char *s2)
{
	size_t l1, l2 = strlen(s2);

	if (!l2)
		return (char *)s1;

	for (l1 = strlen(s1); l1 >= l2; --l1, ++s1)
		if (!memcmp(s1, s2, l2))
			return (char *)s1;

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
