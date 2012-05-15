/*
 * libxlu_cfg.c - xl configuration file parsing: setup and helper functions
 *
 * Copyright (C) 2010      Citrix Ltd.
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


#include "libxl_osdeps.h" /* must come before any other headers */

#include <limits.h>

#include "libxlu_internal.h"
#include "libxlu_cfg_y.h"
#include "libxlu_cfg_l.h"
#include "libxlu_cfg_i.h"

XLU_Config *xlu_cfg_init(FILE *report, const char *report_source) {
    XLU_Config *cfg;

    cfg= malloc(sizeof(*cfg));
    if (!cfg) return 0;

    cfg->report= report;
    cfg->config_source= strdup(report_source);
    if (!cfg->config_source) { free(cfg); return 0; }

    cfg->settings= 0;
    return cfg;
}

static int ctx_prep(CfgParseContext *ctx, XLU_Config *cfg) {
    int e;

    ctx->cfg= cfg;
    ctx->err= 0;
    ctx->lexerrlineno= -1;
    ctx->likely_python= 0;
    ctx->scanner= 0;

    e= xlu__cfg_yylex_init_extra(ctx, &ctx->scanner);
    if (e) {
        fprintf(cfg->report,"%s: unable to create scanner: %s\n",
                cfg->config_source, strerror(e));
        return e;
    }
    return 0;
}

static void ctx_dispose(CfgParseContext *ctx) {
    if (ctx->scanner) xlu__cfg_yylex_destroy(ctx->scanner);
}

static void parse(CfgParseContext *ctx) {
    /* On return, ctx.err will be updated with the error status. */
    int r;

    xlu__cfg_yyset_lineno(1, ctx->scanner);

    r= xlu__cfg_yyparse(ctx);
    if (r) assert(ctx->err);

    if (ctx->err && ctx->likely_python) {
        fputs(
 "warning: Config file looks like it contains Python code.\n"
 "warning:  Arbitrary Python is no longer supported.\n"
 "warning:  See http://wiki.xen.org/wiki/PythonInXlConfig\n",
              ctx->cfg->report);
    }
}

int xlu_cfg_readfile(XLU_Config *cfg, const char *real_filename) {
    FILE *f = 0;
    int e;

    CfgParseContext ctx;
    e = ctx_prep(&ctx, cfg);
    if (e) { ctx.err= e; goto xe; }

    f= fopen(real_filename, "r");
    if (!f) {
        ctx.err = errno;
        fprintf(cfg->report,"%s: unable to open configuration file: %s\n",
                real_filename, strerror(e));
        goto xe;
    }

    xlu__cfg_yyrestart(f, ctx.scanner);

    parse(&ctx);

 xe:
    ctx_dispose(&ctx);
    if (f) fclose(f);

    return ctx.err;
}

int xlu_cfg_readdata(XLU_Config *cfg, const char *data, int length) {
    int e;
    YY_BUFFER_STATE buf= 0;

    CfgParseContext ctx;
    e= ctx_prep(&ctx, cfg);
    if (e) { ctx.err= e; goto xe; }

    buf = xlu__cfg_yy_scan_bytes(data, length, ctx.scanner);
    if (!buf) {
        fprintf(cfg->report,"%s: unable to allocate scanner buffer\n",
                cfg->config_source);
        ctx.err= ENOMEM;
        goto xe;
    }

    parse(&ctx);

 xe:
    if (buf) xlu__cfg_yy_delete_buffer(buf, ctx.scanner);
    ctx_dispose(&ctx);

    return ctx.err;
}

void xlu__cfg_set_free(XLU_ConfigSetting *set) {
    int i;

    if (!set) return;
    free(set->name);
    for (i=0; i<set->nvalues; i++)
        free(set->values[i]);
    free(set->values);
    free(set);
}

void xlu_cfg_destroy(XLU_Config *cfg) {
    XLU_ConfigSetting *set, *set_next;

    for (set= cfg->settings;
         set;
         set= set_next) {
        set_next= set->next;
        xlu__cfg_set_free(set);
    }
    free(cfg->config_source);
    free(cfg);
}

static XLU_ConfigSetting *find(const XLU_Config *cfg, const char *n) {
    XLU_ConfigSetting *set;

    for (set= cfg->settings;
         set;
         set= set->next)
        if (!strcmp(set->name, n))
            return set;
    return 0;
}

static int find_atom(const XLU_Config *cfg, const char *n,
                     XLU_ConfigSetting **set_r, int dont_warn) {
    XLU_ConfigSetting *set;

    set= find(cfg,n);
    if (!set) return ESRCH;

    if (set->avalues!=1) {
        if (!dont_warn)
            fprintf(cfg->report,
                    "%s:%d: warning: parameter `%s' is"
                    " a list but should be a single value\n",
                    cfg->config_source, set->lineno, n);
        return EINVAL;
    }
    *set_r= set;
    return 0;
}

int xlu_cfg_get_string(const XLU_Config *cfg, const char *n,
                       const char **value_r, int dont_warn) {
    XLU_ConfigSetting *set;
    int e;

    e= find_atom(cfg,n,&set,dont_warn);  if (e) return e;
    *value_r= set->values[0];
    return 0;
}

int xlu_cfg_replace_string(const XLU_Config *cfg, const char *n,
                           char **value_r, int dont_warn) {
    XLU_ConfigSetting *set;
    int e;

    e= find_atom(cfg,n,&set,dont_warn);  if (e) return e;
    free(*value_r);
    *value_r= strdup(set->values[0]);
    return 0;
}

int xlu_cfg_get_long(const XLU_Config *cfg, const char *n,
                     long *value_r, int dont_warn) {
    long l;
    XLU_ConfigSetting *set;
    int e;
    char *ep;

    e= find_atom(cfg,n,&set,dont_warn);  if (e) return e;
    errno= 0; l= strtol(set->values[0], &ep, 0);
    e= errno;
    if (errno) {
        e= errno;
        assert(e==EINVAL || e==ERANGE);
        if (!dont_warn)
            fprintf(cfg->report,
                    "%s:%d: warning: parameter `%s' could not be parsed"
                    " as a number: %s\n",
                    cfg->config_source, set->lineno, n, strerror(e));
        return e;
    }
    if (*ep || ep==set->values[0]) {
        if (!dont_warn)
            fprintf(cfg->report,
                    "%s:%d: warning: parameter `%s' is not a valid number\n",
                    cfg->config_source, set->lineno, n);
        return EINVAL;
    }
    *value_r= l;
    return 0;
}

int xlu_cfg_get_defbool(const XLU_Config *cfg, const char *n, libxl_defbool *b,
                     int dont_warn)
{
    int ret;
    long l;

    ret = xlu_cfg_get_long(cfg, n, &l, dont_warn);
    if (ret) return ret;
    libxl_defbool_set(b, !!l);
    return 0;
}

int xlu_cfg_get_list(const XLU_Config *cfg, const char *n,
                     XLU_ConfigList **list_r, int *entries_r, int dont_warn) {
    XLU_ConfigSetting *set;
    set= find(cfg,n);  if (!set) return ESRCH;
    if (set->avalues==1) {
        if (!dont_warn) {
            fprintf(cfg->report,
                    "%s:%d: warning: parameter `%s' is a single value"
                    " but should be a list\n",
                    cfg->config_source, set->lineno, n);
        }
        return EINVAL;
    }
    if (list_r) *list_r= set;
    if (entries_r) *entries_r= set->nvalues;
    return 0;
}

int xlu_cfg_get_list_as_string_list(const XLU_Config *cfg, const char *n,
                     libxl_string_list *psl, int dont_warn) {
    int i, rc, nr;
    XLU_ConfigList *list;
    libxl_string_list sl;

    rc = xlu_cfg_get_list(cfg, n, &list, &nr, dont_warn);
    if (rc)  return rc;

    sl = malloc(sizeof(char*)*(nr + 1));
    if (sl == NULL) return ENOMEM;

    for (i=0; i<nr; i++) {
        const char *a = xlu_cfg_get_listitem(list, i);
        sl[i] = a ? strdup(a) : NULL;
    }

    sl[nr] = NULL;

    *psl = sl;
    return 0;
}

const char *xlu_cfg_get_listitem(const XLU_ConfigList *set, int entry) {
    if (entry < 0 || entry >= set->nvalues) return 0;
    return set->values[entry];
}


XLU_ConfigSetting *xlu__cfg_set_mk(CfgParseContext *ctx,
                                   int alloc, char *atom) {
    XLU_ConfigSetting *set= 0;

    if (ctx->err) goto x;
    assert(!!alloc == !!atom);

    set= malloc(sizeof(*set));
    if (!set) goto xe;

    set->name= 0; /* tbd */
    set->avalues= alloc;

    if (!alloc) {
        set->nvalues= 0;
        set->values= 0;
    } else {
        set->values= malloc(sizeof(*set->values) * alloc);
        if (!set->values) goto xe;

        set->nvalues= 1;
        set->values[0]= atom;
    }
    return set;

 xe:
    ctx->err= errno;
 x:
    free(set);
    free(atom);
    return 0;
}

void xlu__cfg_set_add(CfgParseContext *ctx, XLU_ConfigSetting *set,
                      char *atom) {
    if (ctx->err) return;

    assert(atom);

    if (set->nvalues >= set->avalues) {
        int new_avalues;
        char **new_values;

        if (set->avalues > INT_MAX / 100) { ctx->err= ERANGE; return; }
        new_avalues= set->avalues * 4;
        new_values= realloc(set->values,
                            sizeof(*new_values) * new_avalues);
        if (!new_values) { ctx->err= errno; free(atom); return; }
        set->values= new_values;
        set->avalues= new_avalues;
    }
    set->values[set->nvalues++]= atom;
}

void xlu__cfg_set_store(CfgParseContext *ctx, char *name,
                        XLU_ConfigSetting *set, int lineno) {
    if (ctx->err) return;

    assert(name);
    set->name= name;
    set->lineno= lineno;
    set->next= ctx->cfg->settings;
    ctx->cfg->settings= set;
}

char *xlu__cfgl_strdup(CfgParseContext *ctx, const char *src) {
    char *result;

    if (ctx->err) return 0;
    result= strdup(src);
    if (!result) ctx->err= errno;
    return result;
}

char *xlu__cfgl_dequote(CfgParseContext *ctx, const char *src) {
    char *result;
    const char *p;
    char *q;
    int len, c, nc;

    if (ctx->err) return 0;

    len= strlen(src);
    assert(len>=2 && src[0]==src[len-1]);

    result= malloc(len-1);
    if (!result) { ctx->err= errno; return 0; }

    q= result;

    for (p= src+1;
         p < src+len-1;
         ) {
        c= *p++;
        if (c=='\\') {
            assert(p < src+len-1);
            nc= *p++;
            if (nc=='"' || nc=='\'' || nc=='\\') {
                *q++= nc;
            } else if (nc=='a') { *q++= '\007';
            } else if (nc=='b') { *q++= '\010';
            } else if (nc=='f') { *q++= '\014';
            } else if (nc=='n') { *q++= '\n';
            } else if (nc=='r') { *q++= '\r';
            } else if (nc=='t') { *q++= '\t';
            } else if (nc=='v') { *q++= '\013';
            } else if (nc=='x') {

#define NUMERIC_CHAR(minlen,maxlen,base,basetext) do{                        \
                char numbuf[(maxlen)+1], *ep;                                \
                unsigned long val;                                           \
                                                                             \
                strncpy(numbuf,p,(maxlen));                                  \
                numbuf[(maxlen)]= 0;                                         \
                val= strtoul(numbuf, &ep, (base));                           \
                if (ep <= numbuf+(minlen)) {                                 \
                    xlu__cfgl_lexicalerror(ctx,"invalid digit after"         \
                         " backslash " basetext "numerical character escape" \
                         " in quoted string");                               \
                    ctx->err= EINVAL;                                        \
                    goto x;                                                  \
                }                                                            \
                p += (ep - numbuf);                                          \
 }while(0)

                p++;
                NUMERIC_CHAR(2,2,16,"hex");
            } else if (nc>='0' && nc<='7') {
                NUMERIC_CHAR(1,3,10,"octal");
            }
            assert(p <= src+len-1);
        } else {
            *q++= c;
        }
    }

 x:
    *q++= 0;
    return result;
}

void xlu__cfgl_lexicalerror(CfgParseContext *ctx, char const *msg) {
    YYLTYPE loc;
    loc.first_line= xlu__cfg_yyget_lineno(ctx->scanner);
    xlu__cfg_yyerror(&loc, ctx, msg);
    ctx->lexerrlineno= loc.first_line;
}

void xlu__cfg_yyerror(YYLTYPE *loc, CfgParseContext *ctx, char const *msg) {
    const char *text, *newline;
    int len, lineno;

    lineno= loc->first_line;
    if (lineno <= ctx->lexerrlineno) return;

    text= xlu__cfg_yyget_text(ctx->scanner);
    len= xlu__cfg_yyget_leng(ctx->scanner);
    newline= "";
    if (len>0 && text[len-1]=='\n') {
        len--;
        lineno--;
        if (!len) {
            newline= "<newline>";
        }
    }
    while (len>0 && (text[len-1]=='\t' || text[len-1]==' ')) {
        len--;
    }

    fprintf(ctx->cfg->report,
            "%s:%d: config parsing error near %s%.*s%s%s: %s\n",
            ctx->cfg->config_source, lineno,
            len?"`":"", len, text, len?"'":"", newline,
            msg);
    if (!ctx->err) ctx->err= EINVAL;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
