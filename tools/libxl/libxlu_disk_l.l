/* -*- fundamental -*- */
/*
 * libxlu_disk_l.l - parser for disk specification strings
 *
 * Copyright (C) 2011      Citrix Ltd.
 * Author Ian Jackson <ian.jackson@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

/*
 * Parsing the old xm/xend/xl-4.1 disk specs is a tricky problem,
 * because the target string might in theory contain "," which is the
 * delimiter we use for stripping off things on the RHS, and ":",
 * which is the delimiter we use for stripping off things on the LHS.
 *
 * In this parser we do not support such target strings in the old
 * syntax; if the target string has to contain "," or ":" the new
 * syntax's "target=" should be used.
 */

%top{
#include "libxl_osdeps.h" /* must come before any other headers */
}

%{
#include "libxlu_disk_i.h"

#define YY_NO_INPUT

/* Some versions of flex have a bug (Fedora bugzilla 612465) which causes
 * it to fail to declare these functions, which it defines.  So declare
 * them ourselves.  Hopefully we won't have to simultaneously support
 * a flex version which declares these differently somehow. */
int xlu__disk_yyget_column(yyscan_t yyscanner);
void xlu__disk_yyset_column(int  column_no, yyscan_t yyscanner);


/*----- useful macros and functions used in actions -----
 * we use macros in the actual rules to keep the actions short
 * and particularly to avoid repeating boilerplate values such as
 * DPC->disk, yytext, etc. */

/* Sets an enum, checking it hasn't already been set to a different value  */
#define DSET(dpc,member,enumname,str,valname) do{			\
	if (dpc->disk->member != LIBXL_DISK_##enumname##_UNKNOWN &&	\
	    dpc->disk->member != LIBXL_DISK_##enumname##_##valname) {	\
	    xlu__disk_err(dpc, str, TOSTRING(member) " respecified");	\
	} else {							\
	    dpc->disk->member = LIBXL_DISK_##enumname##_##valname;	\
	}								\
    }while(0)

/* For actions whose patterns contain '=', finds the start of the value */
#define FROMEQUALS (strchr(yytext,'=')+1)

/* Chops the delimiter off, modifying yytext and yyleng. */
#define STRIP(delim) do{                                                \
	if (yyleng>0 && yytext[yyleng-1]==(delim))                      \
	    yytext[--yyleng] = 0;                                       \
    }while(0)

/* Sets a string value, checking it hasn't been set already. */
#define SAVESTRING(what,loc,val) do{					\
	savestring(DPC, what " respecified", &DPC->disk->loc, (val));	\
    }while(0)
static void savestring(DiskParseContext *dpc, const char *what_respecified,
		       char **update, const char *value) {
    if (*update) {
        if (**update) { xlu__disk_err(dpc,value,what_respecified); return; }
        free(*update); /* do not complain about overwriting empty strings */
    }
    *update = strdup(value);
}

#define DPC dpc /* our convention in lexer helper functions */

/* Sets ->readwrite from the string.  This ought to be an enum, perhaps. */
static void setaccess(DiskParseContext *dpc, const char *str) {
    if (!strcmp(str, "r") || !strcmp(str, "ro")) {
        dpc->disk->readwrite = 0;
    } else if (!strcmp(str, "rw") || !strcmp(str, "w") || !strcmp(str,"")) {
	dpc->disk->readwrite = 1;
    } else {
	xlu__disk_err(dpc,str,"unknown value for access");
    }
}

/* Sets ->format from the string.  IDL should provide something for this. */
static void setformat(DiskParseContext *dpc, const char *str) {
    if      (!strcmp(str,""))       DSET(dpc,format,FORMAT,str,RAW);
    else if (!strcmp(str,"raw"))    DSET(dpc,format,FORMAT,str,RAW);
    else if (!strcmp(str,"qcow"))   DSET(dpc,format,FORMAT,str,QCOW);
    else if (!strcmp(str,"qcow2"))  DSET(dpc,format,FORMAT,str,QCOW2);
    else if (!strcmp(str,"vhd"))    DSET(dpc,format,FORMAT,str,VHD);
    else if (!strcmp(str,"empty"))  DSET(dpc,format,FORMAT,str,EMPTY);
    else xlu__disk_err(dpc,str,"unknown value for format");
}

/* Sets ->backend from the string.  IDL should provide something for this. */
static void setbackendtype(DiskParseContext *dpc, const char *str) {
    if (     !strcmp(str,"phy"))   DSET(dpc,backend,BACKEND,str,PHY);
    else if (!strcmp(str,"tap"))   DSET(dpc,backend,BACKEND,str,TAP);
    else if (!strcmp(str,"qdisk")) DSET(dpc,backend,BACKEND,str,QDISK);
    else xlu__disk_err(dpc,str,"unknown value for backendtype");
}

#define DEPRECATE(usewhatinstead) /* not currently reported */

/* Handles a vdev positional parameter which includes a devtype. */
static int vdev_and_devtype(DiskParseContext *dpc, char *str) {
    /* returns 1 if it was <vdev>:<devtype>, 0 (doing nothing) otherwise */
    char *colon = strrchr(str, ':');
    if (!colon)
        return 0;

    DEPRECATE("use `devtype=...'");
    *colon++ = 0;
    SAVESTRING("vdev", vdev, str);

    if (!strcmp(colon,"cdrom")) {
        DPC->disk->is_cdrom = 1;
    } else if (!strcmp(colon,"disk")) {
        DPC->disk->is_cdrom = 0;
    } else {
        xlu__disk_err(DPC,colon,"unknown deprecated type");
    }
    return 1;
}

#undef DPC /* needs to be defined differently the actual lexer */
#define DPC ((DiskParseContext*)yyextra)

%}

%option warn
%option nodefault
%option batch
%option 8bit
%option noyywrap
%option reentrant
%option prefix="xlu__disk_yy"
%option nounput

%x LEXERR

%%

 /*----- the scanner rules which do the parsing -----*/

[ \t\n]+/([^ \t\n].*)? { /* ignore whitespace before parameters */ }

 /* ordinary parameters setting enums or strings */

format=[^,]*,?	{ STRIP(','); setformat(DPC, FROMEQUALS); }

cdrom,?		{ DPC->disk->is_cdrom = 1; }
devtype=cdrom,?	{ DPC->disk->is_cdrom = 1; }
devtype=disk,?	{ DPC->disk->is_cdrom = 0; }
devtype=[^,]*,?	{ xlu__disk_err(DPC,yytext,"unknown value for type"); }

access=[^,]*,?	{ STRIP(','); setaccess(DPC, FROMEQUALS); }
backend=[^,]*,? { STRIP(','); SAVESTRING("backend", backend_domname, FROMEQUALS); }
backendtype=[^,]*,? { STRIP(','); setbackendtype(DPC,FROMEQUALS); }

vdev=[^,]*,?	{ STRIP(','); SAVESTRING("vdev", vdev, FROMEQUALS); }
script=[^,]*,?	{ STRIP(','); SAVESTRING("script", script, FROMEQUALS); }

 /* the target magic parameter, eats the rest of the string */

target=.*	{ STRIP(','); SAVESTRING("target", pdev_path, FROMEQUALS); }

 /* unknown parameters */

[a-z][-a-z0-9]*=[^,],? { xlu__disk_err(DPC,yytext,"unknown parameter"); }

 /* deprecated prefixes */

  /* the "/.*" in these patterns ensures that they count as if they
   * matched the whole string, so these patterns take precedence */

(raw|qcow2?|vhd):/.* {
                    STRIP(':');
                    DPC->had_depr_prefix=1; DEPRECATE("use `[format=]...,'");
                    setformat(DPC, yytext);
                 }

(iscsi|e?nbd|drbd):/.* {
                    char *newscript;
                    STRIP(':');
                    DPC->had_depr_prefix=1; DEPRECATE("use `script=...'");
                    if (asprintf(&newscript, "block-%s", yytext) < 0) {
                            xlu__disk_err(DPC,yytext,"unable to format script");
                            return 0;
                    }
                    savestring(DPC, "script respecified",
                               &DPC->disk->script, newscript);
                    free(newscript);
                }

tapdisk:/.*	{ DPC->had_depr_prefix=1; DEPRECATE(0); }
tap2?:/.*	{ DPC->had_depr_prefix=1; DEPRECATE(0); }
aio:/.*		{ DPC->had_depr_prefix=1; DEPRECATE(0); }
ioemu:/.*	{ DPC->had_depr_prefix=1; DEPRECATE(0); }
file:/.*	{ DPC->had_depr_prefix=1; DEPRECATE(0); }
phy:/.*		{ DPC->had_depr_prefix=1; DEPRECATE(0); }

[a-z][a-z0-9]*:/([^a-z0-9].*)? {
		  xlu__disk_err(DPC,yytext,"unknown deprecated disk prefix");
		  return 0;
		}

 /* positional parameters */

[^=,]*,|[^=,]+,?  {
    STRIP(',');

    if (DPC->err) {
        /* previous errors may just lead to subsequent ones */
    } else if (!DPC->disk->pdev_path) {
        SAVESTRING("target", pdev_path, yytext);
    } else if (!DPC->had_depr_prefix &&
               DPC->disk->format == LIBXL_DISK_FORMAT_UNKNOWN) {
        if (!*DPC->disk->pdev_path && vdev_and_devtype(DPC,yytext)) {
            DPC->disk->format = LIBXL_DISK_FORMAT_EMPTY;
        } else {
            setformat(DPC,yytext);
        }
    } else if (!DPC->disk->vdev) {
        if (!vdev_and_devtype(DPC,yytext))
            SAVESTRING("vdev", vdev, yytext);
    } else if (!DPC->access_set) {
        DPC->access_set = 1;
        setaccess(DPC,yytext);
    } else {
        xlu__disk_err(DPC,yytext,"too many positional parameters");
        return 0; /* don't print any more errors */
    }
}

. {
    BEGIN(LEXERR);
    yymore();
}
<LEXERR>.* {
    xlu__disk_err(DPC,yytext,"bad disk syntax"); return 0;
}
