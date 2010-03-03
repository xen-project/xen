/* -*- fundamental -*- */

%{
#include "libxlu_cfg_i.h"

#define ctx ((CfgParseContext*)yyextra)
#define YY_NO_INPUT

#define GOT(x) do{                \
    yylloc->first_line= yylineno; \
    return (x);                   \
  }while(0)

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

[a-z][_0-9a-z]*         {
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
