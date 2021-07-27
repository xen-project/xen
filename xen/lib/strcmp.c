/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>

/**
 * strcmp - Compare two strings
 * @cs: One string
 * @ct: Another string
 */
int (strcmp)(const char *cs, const char *ct)
{
	unsigned char *csu = (unsigned char *)cs;
	unsigned char *ctu = (unsigned char *)ct;
	int res;

	while (1) {
		if ((res = *csu - *ctu++) != 0 || !*csu++)
			break;
	}

	return res;
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
