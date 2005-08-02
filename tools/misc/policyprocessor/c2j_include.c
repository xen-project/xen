/****************************************************************
 * c2j_include.c
 *
 * Copyright (C) 2005 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This tool makes some constants from acm.h available to the
 * java policyprocessor for version checking.
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#include <xen/acm.h>

char *filename = "policy_version.java";

int main(int argc, char **argv)
{

    FILE *fd;
    if ((fd = fopen(filename, "w")) <= 0)
    {
        printf("File %s not found.\n", filename);
        exit(-ENOENT);
    }

    fprintf(fd, "/*\n * This file was automatically generated\n");
    fprintf(fd, " * Do not change it manually!\n */\n");
    fprintf(fd, "public class policy_version {\n");
    fprintf(fd, "	final int ACM_POLICY_VERSION = %x;\n",
            ACM_POLICY_VERSION);
    fprintf(fd, "	final int ACM_CHWALL_VERSION = %x;\n",
            ACM_CHWALL_VERSION);
    fprintf(fd, "	final int ACM_STE_VERSION = %x;\n",
            ACM_STE_VERSION);
    fprintf(fd, "}\n");
    fclose(fd);
    return 0;
}
