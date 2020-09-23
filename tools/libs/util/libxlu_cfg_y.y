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
  XLU_ConfigValue *value;
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
%token OP_ADD "+="

%type <value>                             value valuelist values
%destructor { xlu__cfg_value_free($$); }  value valuelist values

%%

file:  stmts
 |     stmts assignment

stmts:  /* empty */
 |      stmts stmt

stmt:   assignment endstmt
 |      endstmt
 |      error NEWLINE

assignment: IDENT '=' value { xlu__cfg_set_store(ctx,$1,XLU_OP_ASSIGNMENT,$3,@3.first_line); }
 |          IDENT "+=" value { xlu__cfg_set_store(ctx,$1,XLU_OP_ADDITION,$3,@3.first_line); }

endstmt: NEWLINE
 |      ';'

value:  atom                         { $$= xlu__cfg_string_mk(ctx,$1,&@1); }
 |      '[' nlok valuelist ']'       { $$= $3; }

atom:   STRING                   { $$= $1; }
 |      NUMBER                   { $$= $1; }

valuelist: /* empty */           { $$= xlu__cfg_list_mk(ctx,NULL,&yylloc); }
 |      values                  { $$= $1; }
 |      values ',' nlok         { $$= $1; }

values: value nlok                  { $$= xlu__cfg_list_mk(ctx,$1,&@1); }
 |      values ',' nlok value nlok  { xlu__cfg_list_append(ctx,$1,$4); $$= $1; }

nlok:
        /* nothing */
 |      nlok NEWLINE
