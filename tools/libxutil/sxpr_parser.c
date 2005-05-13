/*
 * Copyright (C) 2001 - 2004 Mike Wray <mike.wray@hp.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or  (at your option) any later version. This library is 
 * distributed in the  hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifdef __KERNEL__
#  include <linux/config.h>
#  include <linux/module.h>
#  include <linux/kernel.h>
#  include <linux/string.h>
#  include <linux/errno.h>
#else
#  include <stdlib.h>
#  include <errno.h>
#endif

#include "iostream.h"
#include "lexis.h"
#include "sxpr_parser.h"
#include "sys_string.h"
#include "enum.h"

/** @file
 * Sxpr parsing.
 *
 * So that the parser does not leak memory, all sxprs constructed by
 * the parser must be freed on error.  On successful parse the sxpr
 * returned becomes the responsibility of the caller.
 *
 * @author Mike Wray <mike.wray@hpl.hp.com>
 */

#define dprintf(fmt, args...) IOStream_print(iostdout, "[DEBUG] %s" fmt, __FUNCTION__, ##args)
#undef printf
#define printf(fmt, args...)   IOStream_print(iostdout, fmt, ##args)

static void reset(Parser *z);
static int inputchar(Parser *p, char c);
static int savechar(Parser *p, char c);
extern void parse_error(Parser *in);
extern void parse_error_id(Parser *in, ParseErrorId id);

static int begin_start(Parser *p, char c);
static int state_start(Parser *p, char c);
static int end_start(Parser *p);

static int begin_comment(Parser *p, char c);
static int state_comment(Parser *p, char c);
static int end_comment(Parser *p);

static int begin_string(Parser *p, char c);
static int state_string(Parser *p, char c);
static int end_string(Parser *p);
static int state_escape(Parser *p, char c);
static int state_octal(Parser *p, char c);
static int state_hex(Parser *p, char c);

static int begin_atom(Parser *p, char c);
static int state_atom(Parser *p, char c);
static int end_atom(Parser *p);

static int state_list(Parser *p, char c);
static int begin_list(Parser *p, char c);
static int end_list(Parser *p);

/** Print a parse error.
 *
 * @param in parser
 * @param msg format followed by printf arguments
 */
void eprintf(Parser *in, char *msg, ...){
    va_list args;
    if(in->error_out){
        va_start(args, msg);
        IOStream_vprint(in->error_out, msg, args);
        va_end(args);
    }
}

/** Print a parse warning.
 *
 * @param in parser
 * @param msg format followed by printf arguments
 */
void wprintf(Parser *in, char *msg, ...){
    va_list args;
    if(in->error_out){
        va_start(args, msg);
        IOStream_vprint(in->error_out, msg, args);
        va_end(args);
    }
}

/*============================================================================*/

/** Record defining the message for a parse error. */
typedef struct {
  ParseErrorId id;
  char *message;
} ParseError;

/** Format for printing parse error messages. */
#define PARSE_ERR_FMT "parse error> line %3d, column %2d: %s"

/** Message catalog for the parse error codes. */
static ParseError catalog[] = {
  { PARSE_ERR_UNSPECIFIED,            "unspecified error" },
  { PARSE_ERR_NOMEM,                  "out of memory" },
  { PARSE_ERR_UNEXPECTED_EOF,         "unexpected end of input" },
  { PARSE_ERR_TOKEN_TOO_LONG,         "token too long" },
  { PARSE_ERR_INVALID_SYNTAX,         "syntax error" },
  { PARSE_ERR_INVALID_ESCAPE,         "invalid escape" },
  { 0, NULL }
};

/** Number of entries in the message catalog. */
const static int catalog_n = sizeof(catalog)/sizeof(ParseError);

void ParserState_free(ParserState *z){
    if(!z) return;
    objfree(z->val);
    deallocate(z);
}

int ParserState_new(ParserStateFn *fn, char *name,
                    ParserState *parent, ParserState **val){
    int err = 0;
    ParserState *z;
    z = ALLOCATE(ParserState);
    if(z){
        z->name = name;
        z->fn = fn;
        z->parent = parent;
        z->val = ONULL;
    } else {
        err = -ENOMEM;
    }
    if(!err) *val = z;
    return err;
}

/** Free a parser.
 * No-op if the parser is null.
 *
 * @param z parser 
 */
void Parser_free(Parser *z){
    if(!z) return;
    objfree(z->val);
    z->val = ONONE;
    deallocate(z);
}

/** Create a new parser. The error stream defaults to null.
 */
Parser * Parser_new(void){
    Parser *z = ALLOCATE(Parser);
    int err = -ENOMEM;
  
    if(!z) goto exit;
    err = 0;
    reset(z);
  exit:
    if(err){
        Parser_free(z);
        z = NULL;
    }
    return z;
}

/** Get the next character.
 * Records the character read in the parser,
 * and sets the line and character counts.
 *
 * @param p parser
 * @return error flag: 0 on success, non-zero on error
 */
static int inputchar(Parser *p, char c){
    int err = 0;
    if(c=='\n'){
        p->line_no++;
        p->char_no = 0;
    } else {
        p->char_no++;
    }
    return err;
}

static int savechar(Parser *p, char c){
    int err = 0;
    if(p->buf_i >= p->buf_n){
        err = -ENOMEM;
        goto exit;
    }
    p->buf[p->buf_i] = c;
    p->buf_i++;
  exit:
    return err;
}

int Parser_input_char(Parser *p, char c){
    int err = 0;
    if(at_eof(p)){
        //skip;
    } else {
        inputchar(p, c);
    }
    if(!p->state){
        err = begin_start(p, c);
        if(err) goto exit;
    }
    err = p->state->fn(p, c);
  exit:
    return err;
}

int Parser_input_eof(Parser *p){
    int err = 0;
    p->eof = 1;
    err = Parser_input_char(p, IOSTREAM_EOF);
    return err;
}

int Parser_input(Parser *p, char *buf, int buf_n){
    int err = 0;
    int i = 0;
    if(buf_n <= 0){
        err = Parser_input_eof(p);
        goto exit;
    }
    for(i = 0; i<buf_n; i++){
        err = Parser_input_char(p, buf[i]);
        if(err) goto exit;
    }
  exit:
    err = (err < 0 ? err : buf_n);
    return err;
}

int Parser_push(Parser *p, ParserStateFn *fn, char *name){
    int err = 0;
    err = ParserState_new(fn, name, p->state, &p->state);
    return err;
}
        
int Parser_pop(Parser *p){
    int err = 0;
    ParserState *s = p->state;
    p->state = s->parent;
    if (p->start_state == s) {
        p->start_state = NULL;
    }
    ParserState_free(s);
    return err;
}

int Parser_return(Parser *p){
    int err = 0;
    Sxpr val = ONONE;
    if(!p->state){
        err = -EINVAL;
        goto exit;
    }
    val = p->state->val;
    p->state->val = ONONE;
    err = Parser_pop(p);
    if(err) goto exit;
    if(p->state){
        err = cons_push(&p->state->val, val);
    } else {
        val = nrev(val);
        p->val = val;
    }
  exit:
    if(err){
        objfree(val);
    }
    return err;
}

/** Determine if a character is a separator.
 *
 * @param p parser
 * @param c character to test
 * @return 1 if a separator, 0 otherwise
 */
static int is_separator(Parser *p, char c){
    return in_sep_class(c);
}

/** Return the current token.
 * The return value points at the internal buffer, so
 * it must not be modified (or freed). Use copy_token() if you need a copy.
 *
 * @param p parser
 * @return token
 */
char *peek_token(Parser *p){
    return p->buf;
}

/** Return a copy of the current token.
 * The returned value should be freed when finished with.
 *
 * @param p parser
 * @return copy of token
 */
char *copy_token(Parser *p){
    return strdup(peek_token(p));
}

static int do_intern(Parser *p){
    int err = 0;
    Sxpr obj = intern(peek_token(p));
    if(NOMEMP(obj)){
        err = -ENOMEM;
    } else {
        p->state->val = obj;
    }
    return err;
}

static int do_string(Parser *p){
    int err = 0;
    Sxpr obj;
    obj = string_new(peek_token(p));
    if(NOMEMP(obj)){
        err = -ENOMEM;
    } else {
        p->state->val = obj;
    }
    return err;
}

void newtoken(Parser *p){
    memset(p->buf, 0, p->buf_n);
    p->buf_i = 0;
    p->tok_begin_line = p->line_no;
    p->tok_begin_char = p->char_no;
}

int get_escape(char c, char *d){
    int err = 0;
    switch(c){
    case 'a':            *d = '\a'; break;
    case 'b':            *d = '\b'; break;
    case 'f':            *d = '\f'; break;
    case 'n':            *d = '\n'; break;
    case 'r':            *d = '\r'; break;
    case 't':            *d = '\t'; break;
    case 'v':            *d = '\v'; break;
    case c_escape:       *d = c_escape; break;
    case c_single_quote: *d = c_single_quote; break;
    case c_double_quote: *d = c_double_quote; break;
    default:
        err = -EINVAL;
    }
    return err;
}

int Parser_ready(Parser *p){
    return CONSP(p->val) || (p->start_state && CONSP(p->start_state->val));
}

Sxpr Parser_get_val(Parser *p){
    Sxpr v = ONONE;
    if(CONSP(p->val)){
        v = CAR(p->val);
        p->val = CDR(p->val);
    } else if (CONSP(p->start_state->val)){
        p->val = p->start_state->val;
        p->val = nrev(p->val);
        p->start_state->val = ONULL;
        v = CAR(p->val);
        p->val = CDR(p->val);
    }        
    return v;
}

Sxpr Parser_get_all(Parser *p){
    Sxpr v = ONULL;
    if(CONSP(p->val)){
        v = p->val;
        p->val = ONONE;
    } else if(p->start_state && CONSP(p->start_state->val)){
        v = p->start_state->val;
        p->start_state->val = ONULL;
        v = nrev(v);
    }
    return v;
}
    
int begin_start(Parser *p, char c){
    int err = 0;
    err = Parser_push(p, state_start, "start");
    if(err) goto exit;
    p->start_state = p->state;
  exit:
    return err;
}

int state_start(Parser *p, char c){
    int err = 0;
    if(at_eof(p)){
        err = end_start(p);
    } else if(in_space_class(c)){
        //skip
    } else if(in_comment_class(c)){
        begin_comment(p, c);
    } else if(c == c_list_open){
        begin_list(p, c);
    } else if(c == c_list_close){
        parse_error(p);
        err = -EINVAL;
    } else if(in_string_quote_class(c)){
        begin_string(p, c);
    } else if(in_printable_class(c)){
        begin_atom(p, c);
    } else if(c == 0x04){
        //ctrl-D, EOT: end-of-text.
        Parser_input_eof(p);
    } else {
        parse_error(p);
        err = -EINVAL;
    }
    return err;
}

int end_start(Parser *p){
    int err = 0;
    err = Parser_return(p);
    return err;
}

int begin_comment(Parser *p, char c){
    int err = 0;
    err = Parser_push(p, state_comment, "comment");
    if(err) goto exit;
    err = inputchar(p, c);
  exit:
    return err;
}

int state_comment(Parser *p, char c){
    int err = 0;
    if(c == '\n' || at_eof(p)){
        err = end_comment(p);
    } else {
        err = inputchar(p, c);
    }
    return err;
}

int end_comment(Parser *p){
    return Parser_pop(p);
}

int begin_string(Parser *p, char c){
    int err = 0;
    err = Parser_push(p, state_string, "string");
    if(err) goto exit;
    newtoken(p);
    p->state->delim = c;
  exit:
    return err;
}

int state_string(Parser *p, char c){
    int err = 0;
    if(at_eof(p)){
        parse_error_id(p, PARSE_ERR_UNEXPECTED_EOF);
        err = -EINVAL;
    } else if(c == p->state->delim){
        err = end_string(p);
    } else if(c == '\\'){
        err = Parser_push(p, state_escape, "escape");
    } else {
        err = savechar(p, c);
    }
    return err;
}

int end_string(Parser *p){
    int err = 0;
    err = do_string(p);
    if(err) goto exit;
    err = Parser_return(p);
  exit:
    return err;
}

int state_escape(Parser *p, char c){
    int err = 0;
    char d;
    if(at_eof(p)){
        parse_error_id(p, PARSE_ERR_UNEXPECTED_EOF);
        err = -EINVAL;
        goto exit;
    }
    if(get_escape(c, &d) == 0){
        err = savechar(p, d);
        if(err) goto exit;
        err = Parser_pop(p);
    } else if(c == 'x'){
        p->state->fn = state_hex;
        p->state->ival = 0;
        p->state->count = 0;
    } else {
        p->state->fn = state_octal;
        p->state->ival = 0;
        p->state->count = 0;
        err = Parser_input_char(p, c);
    }
  exit:
    return err;
}

int octaldone(Parser *p){
    int err = 0;
    char d = (char)(p->state->ival & 0xff);
    err = Parser_pop(p);
    if(err) goto exit;
    err = Parser_input_char(p, d);
  exit:
    return err;
}

int octaldigit(Parser *p, char c){
    int err = 0;
    p->state->ival *= 8;
    p->state->ival += c - '0'; 
    p->state->count++;
    if(err) goto exit;
    if(p->state->ival < 0 || p->state->ival > 0xff){
        parse_error(p);
        err = -EINVAL;
        goto exit;
    }
    if(p->state->count == 3){
        err = octaldone(p);
    }
  exit:
    return err;
}

int state_octal(Parser *p, char c){
    int err = 0;
    if(at_eof(p)){
        parse_error_id(p, PARSE_ERR_UNEXPECTED_EOF);
        err = -EINVAL;
        goto exit;
    } else if('0' <= c && c <= '7'){
        err = octaldigit(p, c);
    } else {
        err = octaldone(p);
        if(err) goto exit;
        Parser_input_char(p, c);
    }
  exit:
    return err;
}

int hexdone(Parser *p){
    int err = 0;
    char d = (char)(p->state->ival & 0xff);
    err = Parser_pop(p);
    if(err) goto exit;
    err = Parser_input_char(p, d);
  exit:
    return err;
}
    
int hexdigit(Parser *p, char c, char d){
    int err = 0;
    p->state->ival *= 16;
    p->state->ival += c - d; 
    p->state->count++;
    if(err) goto exit;
    if(p->state->ival < 0 || p->state->ival > 0xff){
        parse_error(p);
        err = -EINVAL;
        goto exit;
    }
    if(p->state->count == 2){
        err = hexdone(p);
    }
  exit:
    return err;
}
    
int state_hex(Parser *p, char c){
    int err = 0;
    if(at_eof(p)){
        parse_error_id(p, PARSE_ERR_UNEXPECTED_EOF);
        err = -EINVAL;
        goto exit;
    } else if('0' <= c && c <= '9'){
        err = hexdigit(p, c, '0');
    } else if('A' <= c && c <= 'F'){
        err = hexdigit(p, c, 'A');
    } else if('a' <= c && c <= 'f'){
        err = hexdigit(p, c, 'a');
    } else if(p->state->count){
        err =hexdone(p);
        if(err) goto exit;
        Parser_input_char(p, c);
    }
  exit:
    return err;
}

int begin_atom(Parser *p, char c){
    int err = 0;
    err = Parser_push(p, state_atom, "atom");
    if(err) goto exit;
    newtoken(p);
    err = savechar(p, c);
  exit:
    return err;
}

int state_atom(Parser *p, char c){
    int err = 0;
    if(at_eof(p)){
        err = end_atom(p);
    } else if(is_separator(p, c) ||
              in_space_class(c) ||
              in_comment_class(c)){
        err = end_atom(p);
        if(err) goto exit;
        err = Parser_input_char(p, c);
    } else {
        err = savechar(p, c);
    }
  exit:
    return err;
}

int end_atom(Parser *p){
    int err = 0;
    err = do_intern(p);
    if(err) goto exit;
    err = Parser_return(p);
  exit:
    return err;
}

int state_list(Parser *p, char c){
    int err = 0;
    if(at_eof(p)){
        parse_error_id(p, PARSE_ERR_UNEXPECTED_EOF);
        err = -EINVAL;
    } else if(c == c_list_close){
        p->state->val = nrev(p->state->val);
        err = end_list(p);
    } else {
        err = state_start(p, c);
    }
    return err;
    
}

int begin_list(Parser *p, char c){
    return Parser_push(p, state_list, "list");
}

int end_list(Parser *p){
    return Parser_return(p);
}

/** Reset the fields of a parser to initial values.
 *
 * @param z parser
 */
static void reset(Parser *z){
  IOStream *error_out = z->error_out;
  int flags = z->flags;
  memzero(z, sizeof(Parser));
  z->buf_n = sizeof(z->buf) - 1;
  z->buf_i = 0;
  z->line_no = 1;
  z->char_no = 0;
  z->error_out = error_out;
  z->flags = flags;
}

/** Set the parser error stream.
 * Parse errors are reported on the the error stream if it is non-null.
 * 
 * @param z parser
 * @param error_out error stream
 */
void set_error_stream(Parser *z, IOStream *error_out){
  if(z){
    z->error_out = error_out;
  }
}

/** Get the parser error message for an error code.
 *
 * @param id error code
 * @return error message (empty string if the code is unknown)
 */
static char *get_message(ParseErrorId id){
  int i;
  for(i=0; i<catalog_n; i++){
    if(id == catalog[i].id){
      return catalog[i].message;
    }
  }
  return "";
}

/** Get the line number.
 *
 * @param in parser
 */
int get_line(Parser *in){
  return in->line_no;
}

/** Get the column number.
 *
 * @param in parser
 */
int get_column(Parser *in){
  return in->char_no;
}

/** Get the line number the current token started on.
 *
 * @param in parser
 */
int get_tok_line(Parser *in){
  return in->tok_begin_line;
}

/** Get the column number the current token started on.
 *
 * @param in parser
 */
int get_tok_column(Parser *in){
  return in->tok_begin_char;
}

/** Report a parse error.
 * Does nothing if the error stream is null or there is no error.
 *
 * @param in parser
 */
static void report_error(Parser *in){
  if(in->error_out && in->err){
    char *msg = get_message(in->err);
    char *tok = peek_token(in);
    IOStream_print(in->error_out, PARSE_ERR_FMT,
		   get_tok_line(in), get_tok_column(in), msg);
    if(tok && tok[0]){
        IOStream_print(in->error_out, " '%s'", tok);
    }
    IOStream_print(in->error_out, "\n");
  }
}

/** Get the error message for the current parse error code.
 * Does nothing if there is no error.
 *
 * @param in parser
 * @param buf where to place the message
 * @param n maximum number of characters to place in buf
 * @return current error code (zero for no error)
 */
int parse_error_message(Parser *in, char *buf, int n){
    if(in->err){
        char *msg = get_message(in->err);
        snprintf(buf, n, PARSE_ERR_FMT, get_tok_line(in), get_tok_column(in), msg);
    }
    return in->err;
}

/** Flag an unspecified parse error. All subsequent reads will fail.
 *
 * @param in parser
 */
void parse_error(Parser *in){
    parse_error_id(in, PARSE_ERR_INVALID_SYNTAX);
}

/** Flag a parse error. All subsequent reads will fail.
 * Does not change the parser error code if it is already set.
 *
 * @param in parser
 * @param id error code
 */
void parse_error_id(Parser *in, ParseErrorId id){
    if(!in->err){
        in->err = id;
        report_error(in);
    }
}

/** Test if the parser's error flag is set.
 *
 * @param in parser
 * @return 1 if set, 0 otherwise
 */
int has_error(Parser *in){
    return (in->err > 0);
}

/** Test if the parser is at end of input.
 *
 * @param in parser
 * @return 1 if at EOF, 0 otherwise
 */
int at_eof(Parser *p){
    return p->eof;
}

#ifdef SXPR_PARSER_MAIN
/* Stuff for standalone testing. */

#include "file_stream.h"
#include "string_stream.h"

extern int stringof(Sxpr exp, char **s);
int child_string(Sxpr exp, Sxpr key, char **s){
    int err = 0;
    Sxpr val = sxpr_child_value(exp, key, ONONE);
    err = stringof(val, s);
    return err;
}

extern int intof(Sxpr exp, int *v);
int child_int(Sxpr exp, Sxpr key, int *v){
    int err = 0;
    Sxpr val = sxpr_child_value(exp, key, ONONE);
    err = intof(val, v);
    return err;
}

int eval_vnet(Sxpr exp){
    int err = 0;
    Sxpr oid = intern("id");
    int id;
    err = child_int(exp, oid, &id);
    if(err) goto exit;
    dprintf("> vnet id=%d\n", id);
 exit:
    dprintf("< err=%d\n", err);
    return err;
}

int eval_connect(Sxpr exp){
    int err = 0;
    Sxpr ovif = intern("vif");
    Sxpr ovnet = intern("vnet");
    char *vif;
    int vnet;

    err = child_string(exp, ovif, &vif);
    if(err) goto exit;
    err = child_int(exp, ovnet, &vnet);
    if(err) goto exit;
    dprintf("> connect vif=%s vnet=%d\n", vif, vnet);
 exit:
    dprintf("< err=%d\n", err);
    return err;
}

int eval(Sxpr exp){
    int err = 0;
    Sxpr oconnect = intern("connect");
    Sxpr ovnet = intern("vnet");
    
    if(sxpr_elementp(exp, ovnet)){
        err = eval_vnet(exp);
    } else if(sxpr_elementp(exp, oconnect)){
        err = eval_connect(exp);
    } else {
        err = -EINVAL;
    }
    return err;
}

/** Main program for testing.
 * Parses input and prints it.
 *
 * @param argc number of arguments
 * @param argv arguments
 * @return error code
 */
int main(int argc, char *argv[]){
    Parser *pin;
    int err = 0;
    char buf[1024];
    int k;
    Sxpr obj;
    //Sxpr l, x;
    int i = 0;

    pin = Parser_new();
    set_error_stream(pin, iostdout);
    dprintf("> parse...\n");
    while(1){
        k = fread(buf, 1, 1, stdin);
        err = Parser_input(pin, buf, k);
        while(Parser_ready(pin)){
            obj = Parser_get_val(pin);
            printf("obj %d\n", i++);
            objprint(iostdout, obj, 0); printf("\n");
        }
        if(k <= 0) break;
    }
/*     obj = Parser_get_all(pin); */
/*     for(l = obj ; CONSP(l); l = CDR(l)){ */
/*         x = CAR(l); */
/*         objprint(iostdout, x, 0); printf("\n"); */
/*         eval(x); */
/*     } */
    dprintf("> err=%d\n", err);
    return 0;
}
#endif
