/* -*- fundamental -*- */
/*
 * libxlu_cfg_l.l - xl configuration file parsing: lexer
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
#include "libxlu_cfg_i.h"

#define ctx ((CfgParseContext*)yyextra)
#define YY_NO_INPUT

#define GOT(x) do{                \
    yylloc->first_line= yylineno; \
    return (x);                   \
  }while(0)

/* Some versions of flex have a bug (Fedora bugzilla 612465) which causes
 * it to fail to declare these functions, which it defines.  So declare
 * them ourselves.  Hopefully we won't have to simultaneously support
 * a flex version which declares these differently somehow. */
int xlu__cfg_yyget_column(yyscan_t yyscanner);
void xlu__cfg_yyset_column(int  column_no, yyscan_t yyscanner);

%}

%option warn
%option nodefault
%option batch
%option 8bit
%option yylineno
%option noyywrap
%option bison-bridge
%option bison-locations
%option reentrant
%option prefix="xlu__cfg_yy"
%option nounput

%x lexerr

%%

[a-z][._0-9a-z]*        {
                          yylval->string= xlu__cfgl_strdup(ctx,yytext);
                          GOT(IDENT);
                        }
[0-9][0-9a-fx]*         {
                          yylval->string= xlu__cfgl_strdup(ctx,yytext);
                          GOT(NUMBER);
                        }

[ \t]

,                       { GOT(','); }
\[                      { GOT('['); }
\]                      { GOT(']'); }
\+\=                    { GOT(OP_ADD); }
\=                      { GOT('='); }
\;                      { GOT(';'); }

\n|\#.*\n               { yylloc->first_line= yylineno-1; return NEWLINE; }

\'([^\'\\\n]|\\.)*\'    {
                          yylval->string= xlu__cfgl_dequote(ctx,yytext);
                          GOT(STRING);
                        }
\"([^\"\\\n]|\\.)*\"    {
                          yylval->string= xlu__cfgl_dequote(ctx,yytext);
                          GOT(STRING);
                        }

[+-.():]                {
                          ctx->likely_python= 1;
                          BEGIN(lexerr);
                          yymore();
                        }

.                       {
                          BEGIN(lexerr);
                          yymore();
                        }

<lexerr>[^ \t\n]*|[ \t] {
                          xlu__cfgl_lexicalerror(ctx,"lexical error");
                          BEGIN(0);
                        }

<lexerr>\n              {
                          xlu__cfgl_lexicalerror(ctx,"lexical error");
                          BEGIN(0);
                          GOT(NEWLINE);
                        }
