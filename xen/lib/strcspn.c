/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/string.h>

/**
 * strcspn - Calculate the length of the initial substring of @s which does not contain letters in @reject
 * @s: The string to be searched
 * @reject: The string to avoid
 */
size_t (strcspn)(const char *s, const char *reject)
{
       const char *p;

       for (p = s; *p != '\0'; ++p) {
               if (strchr(reject, *p))
                       break;
       }
       return p - s;
}
