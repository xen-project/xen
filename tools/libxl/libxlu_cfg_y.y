/* -*- fundamental -*- */
/*
 * libxlu_cfg_l.y - xl configuration file parsing: parser
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

%{
#define ctx_scanner ctx->scanner
#include "libxlu_cfg_i.h"
#include "libxlu_cfg_l.h"
%}

%union {
  char *string;
  XLU_ConfigSetting *setting;
}

%locations
%pure-parser
%defines
%error-verbose
%name-prefix "xlu__cfg_yy"
%parse-param { CfgParseContext *ctx }
%lex-param { ctx_scanner }

%token <string>                IDENT STRING NUMBER NEWLINE
%type <string>            atom
%destructor { free($$); } atom IDENT STRING NUMBER

%type <setting>                         value valuelist values
%destructor { xlu__cfg_set_free($$); }  value valuelist values

%%

file:  stmts
 |     stmts assignment

stmts:  /* empty */
 |      stmts stmt

stmt:   assignment endstmt
 |      endstmt
 |      error NEWLINE

assignment: IDENT '=' value { xlu__cfg_set_store(ctx,$1,$3,@3.first_line); }

endstmt: NEWLINE
 |      ';'

value:  atom                         { $$= xlu__cfg_set_mk(ctx,1,$1); }
 |      '[' nlok valuelist ']'       { $$= $3; }

atom:   STRING                   { $$= $1; }
 |      NUMBER                   { $$= $1; }

valuelist: /* empty */           { $$= xlu__cfg_set_mk(ctx,0,0); }
 |      values                  { $$= $1; }
 |      values ',' nlok         { $$= $1; }

values: atom nlok                  { $$= xlu__cfg_set_mk(ctx,2,$1); }
 |      values ',' nlok atom nlok  { xlu__cfg_set_add(ctx,$1,$4); $$= $1; }

nlok:
        /* nothing */
 |      nlok NEWLINE
