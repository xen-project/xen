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

#ifndef _XUTIL_SXPR_PARSER_H_
#define _XUTIL_SXPR_PARSER_H_

#include "sxpr.h"
#include "iostream.h"

/** @file
 * Sxpr parsing definitions.
 */

/** Size of a parser input buffer.
 * Tokens read must fit into this size (including trailing null).
 */
#define PARSER_BUF_SIZE 1024

struct Parser;
typedef int ParserStateFn(struct Parser *, char c);

typedef struct ParserState {
    struct ParserState *parent;
    Sxpr val;
    int ival;
    int count;
    char delim;
    ParserStateFn *fn;
    char *name;
} ParserState;

/** Structure representing an input source for the parser.
 * Can read from any IOStream implementation.
 */
typedef struct Parser {
    Sxpr val;
    /** Error reporting stream (null for no reports). */
    IOStream *error_out;
    int eof;
    /** Error flag. Non-zero if there has been a read error. */
    int err;
    /** Line number on input (from 1). */
    int line_no;
    /** Column number of input (reset on new line). */
    int char_no;
    /** Lookahead character. */
    char c;
    /** Buffer for reading tokens. */
    char buf[PARSER_BUF_SIZE];
    /** Size of token buffer. */
    int buf_n;
    int buf_i;
    /** Line the last token started on. */
    int tok_begin_line;
    /** Character number the last token started on. */
    int tok_begin_char;
    /** Parsing flags. */
    int flags;
    ParserState *state;
    ParserState *start_state;
} Parser;

/** Parser error codes. */
typedef enum {
    PARSE_ERR_NONE=0,
    PARSE_ERR_UNSPECIFIED,
    PARSE_ERR_NOMEM,
    PARSE_ERR_UNEXPECTED_EOF,
    PARSE_ERR_TOKEN_TOO_LONG,
    PARSE_ERR_INVALID_SYNTAX,
    PARSE_ERR_INVALID_ESCAPE,
} ParseErrorId;


/** Parser flags. */
//enum {
//};

/** Raise some parser flags.
 *
 * @param in parser
 * @param flags flags mask
 */
inline static void parser_flags_raise(Parser *in, int flags){
    in->flags |= flags;
}

/** Lower some parser flags.
 *
 * @param in parser
 * @param flags flags mask
 */
inline static void parser_flags_lower(Parser *in, int flags){
    in->flags &= ~flags;
}

/** Clear all parser flags.
 *
 * @param in parser
 */
inline static void parser_flags_clear(Parser *in){
    in->flags = 0;
}

extern void Parser_free(Parser *z);
extern Parser * Parser_new(void);
extern int Parser_input(Parser *p, char *buf, int buf_n);
extern int Parser_input_eof(Parser *p);
extern int Parser_input_char(Parser *p, char c);
extern void set_error_stream(Parser *z, IOStream *error_out);

extern int parse_error_message(Parser *in, char *buf, int n);
extern int has_error(Parser *in);
extern int at_eof(Parser *in);

int Parser_ready(Parser *p);
Sxpr Parser_get_val(Parser *p);
Sxpr Parser_get_all(Parser *p);

#endif /* ! _XUTIL_SXPR_PARSER_H_ */
