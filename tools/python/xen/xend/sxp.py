#!/usr/bin/python2
# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""
Input-driven parsing for s-expression (sxp) format.
Create a parser: pin = Parser();
Then call pin.input(buf) with your input.
Call pin.input_eof() when done.
Use pin.read() to see if a value has been parsed, pin.get_val()
to get a parsed value. You can call ready and get_val at any time -
you don't have to wait until after calling input_eof.

"""
from __future__ import generators

import sys
import types
import errno
import string
from StringIO import StringIO

__all__ = [
    "mime_type", 
    "ParseError", 
    "Parser",
    "show",
    "name", 
    "children", 
    "child", 
    "child_value",
    "to_string",
    "from_string",
    "parse", 
    ]

mime_type = "application/sxp"

class ParseError(StandardError):

    def __init__(self, parser, value):
        self.parser = parser
        self.value = value

    def __str__(self):
        return self.value

class ParserState:

    def __init__(self, fn, parent=None):
        self.parent = parent
        self.buf = ''
        self.val = []
        self.fn = fn

    def push(self, fn):
        return ParserState(fn, parent=self)
    
class Parser:

    def __init__(self):
        self.reset()

    def reset(self):
        self.eof = 0
        self.line_no = 0
        self.char_no = 0
        self.state = self.start_state = ParserState(self.state_start)

    def push_state(self, fn):
        self.state = self.state.push(fn)

    def pop_state(self):
        self.state = self.state.parent

    def in_class(self, c, s):
        return s.find(c) >= 0
        
    def in_space_class(self, c):
        return self.in_class(c, ' \t\n\v\f\r')

    def is_separator(self, c):
        return self.in_class(c, '{}()<>[]!;')

    def in_comment_class(self, c):
        return self.in_class(c, '#')

    def in_string_quote_class(self, c):
        return self.in_class(c, '"\'')

    def in_printable_class(self, c):
        return self.in_class(c, string.printable)

    def at_eof(self):
        return self.eof

    def input_eof(self):
        self.eof = 1
        self.input_char(-1)

    def input(self, buf):
        if not buf or len(buf) == 0:
            self.input_eof()
        else:
            for c in buf:
                self.input_char(c)

    def input_char(self, c):
        if self.at_eof():
            pass
        elif c == '\n':
            self.line_no += 1
            self.char_no = 0
        else:
           self.char_no += 1 

        if self.state is None:
            self.state = ParserState(self.state_start)

        self.state.fn(c)

    def ready(self):
        return len(self.start_state.val) > 0

    def get_val(self):
        v = self.start_state.val[0]
        self.start_state.val = self.start_state.val[1:]
        return v

    def get_all(self):
        return self.start_state.val

    def state_start(self, c):
        if self.at_eof() or self.in_space_class(c):
            pass
        elif self.in_comment_class(c):
            self.push_state(self.state_comment)
        elif c == '(':
            self.push_state(self.state_list)
        elif c == ')':
            raise ParseError(self, "syntax error: "+c)
        elif self.in_string_quote_class(c):
            self.push_state(self.state_string)
            self.state.buf = c
        elif self.in_printable_class(c):
            self.push_state(self.state_atom)
            self.state.buf = c
        elif c == chr(4):
            # ctrl-D, EOT: end-of-text.
            self.input_eof()
        else:
            raise ParseError(self, "invalid character: code %d" % ord(c))

    def state_comment(self, c):
        if c == '\n' or self.at_eof():
            self.pop_state()

    def state_string(self, c):
        if self.at_eof():
            raise ParseError(self, "unexpected EOF")
        self.state.buf += c
        # Look out for non-escaped end delimiter
        if self.state.buf[0] == c and self.state.buf[-2] != '\\':
            try: # parse escape sequences but fall back to something simple
                val = eval(compile(self.state.buf,'','eval'))
            except:
                val = self.state.buf[1:-1] # just strip the delimiters
            self.state.parent.val.append(val)
            self.pop_state()
    
    def state_atom(self, c):
        if (self.at_eof() or
            self.is_separator(c) or
            self.in_space_class(c) or
            self.in_comment_class(c)):
            val = self.state.buf
            self.state.parent.val.append(val)
            self.pop_state()
            if not self.at_eof():
                self.input_char(c)
        else:
            self.state.buf += c

    def state_list(self, c):
        if self.at_eof():
            raise ParseError(self, "unexpected EOF")
        elif c == ')':
            val = self.state.val
            self.state.parent.val.append(val)
            self.pop_state()
        else:
            self.state_start(c)

def show(sxpr, out=sys.stdout):
    """Print an sxpr in bracketed (lisp-style) syntax.
    """
    if isinstance(sxpr, types.ListType):
        out.write('(')
        for x in sxpr:
            show(x, out)
            out.write(' ')
        out.write(')')
    else:
        out.write(repr(str(sxpr)))

def name(sxpr):
    """Get the element name of an sxpr, or None if a bad sxpr.
    """
    if isinstance(sxpr, types.StringType):
        return sxpr
    if isinstance(sxpr, types.ListType) and len(sxpr):
        return sxpr[0]
    return None

def children(sxpr, elt=None):
    """Get children of an s-expression @sxpr, optionally filtered by
    element type @elt.
    """
    if not isinstance(sxpr, types.ListType): return []
    val = filter(lambda x: isinstance(x, types.ListType) and len(x) > 0, sxpr)
    if elt:
        val = filter(lambda x,y=elt: x[0] == y, val)
    return val

def child(sxpr, elt=None, idx=0):
    """Get the @idx'th child of the optional filtering type @elt in @sxpr.
    """
    x = children(sxpr, elt)
    if len(x) > idx:
        return x[idx]
    return None

def child_value(sxpr, elt=None):
    """Get the value of the first child of @sxpr with the optional type @elt.
    """
    x = child(sxpr, elt)
    if not isinstance(x, types.ListType) or len(x) < 2:
        return None
    return x[1]

def to_string(sxpr):
    """Convert an s-expression @sxpr to a string.
    """
    io = StringIO()
    show(sxpr, io)
    io.seek(0)
    val = io.getvalue()
    io.close()
    return val

def from_string(str):
    """Create an sxpr list from a given input string @str.
    """
    io = StringIO(str)
    vals = parse(io)
    return vals

def parse(io):
    """Completely parse all input from file @io.
    """
    pin = Parser()
    while 1:
        buf = io.readline()
        pin.input(buf)
        if len(buf) == 0:
            break
    if pin.ready():
        val = pin.get_all()
    else:
        val = None
    return val

   
if __name__ == '__main__':
    pin = Parser()
    buf = sys.stdin.read(1024)
    pin.input(buf)
    while pin.ready():
        print '\n****** val=', pin.get_val()
