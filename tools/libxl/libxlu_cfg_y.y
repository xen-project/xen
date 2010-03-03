/* -*- fundamental -*- */

%{
#define YYLEX_PARAM ctx->scanner
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
%name-prefix="xlu__cfg_yy"
%parse-param { CfgParseContext *ctx }
%lex-param { void *scanner }

%token <string>                IDENT STRING NUMBER NEWLINE
%type <string>            atom
%destructor { free($$); } atom IDENT STRING NUMBER

%type <setting>                         value valuelist values
%destructor { xlu__cfg_set_free($$); }  value valuelist values

%%

file: /* empty */
 |     file setting           

setting: IDENT '=' value      { xlu__cfg_set_store(ctx,$1,$3,@3.first_line); }
                     endstmt
 |      endstmt
 |      error NEWLINE

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
