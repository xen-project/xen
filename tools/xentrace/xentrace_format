#!/usr/bin/env python

# by Mark Williamson, (C) 2004 Intel Research Cambridge

# Program for reformatting trace buffer output according to user-supplied rules

import re, sys, string, signal

def usage():
    print >> sys.stderr, \
          "Usage: " + sys.argv[0] + """ defs-file
          Parses trace data in ASCII format and reformats it according to the
          rules in a file of definitions.  The rules in this file should have
          the format ({ and } show grouping and are not part of the syntax):

          {event_id}{whitespace}{text format string}

          The textual format string may include the format specifiers:
            %(cpu)s, %(tsc), %(event)s, %(1)s, %(2)s, %(3)s, %(4)s, %(5)s

          Which correspond to the CPU number, event ID, timestamp counter and
          the 5 data fields from the trace record.  There should be one such
          rule for each type of event.
          
          Depending on your system and the volume of trace buffer data,
          this script may not be able to keep up with the output of xentrace
          if it is piped directly.  In these circumstances you should have
          xentrace output to a file for processing off-line.
          """
    sys.exit(1)

def read_defs(defs_file):
    defs = {}
    
    fd = open(defs_file)

    reg = re.compile('(\d+)\s+(\S.*)')

    while True:
        line = fd.readline()
        if not line:
            break
        
        m = reg.match(line)

        if not m: print >> sys.stderr, "Bad format file" ; sys.exit(1)
        
        defs[m.group(1)] = m.group(2)

    return defs

def sighand(x,y):
    global interrupted
    interrupted = 1

##### Main code

if len(sys.argv) < 2:
    usage()

signal.signal(signal.SIGTERM, sighand)
signal.signal(signal.SIGHUP,  sighand)
signal.signal(signal.SIGINT,  sighand)

interrupted = 0

defs = read_defs(sys.argv[1])

reg = re.compile('(\d+) (\d+) (\d+) (.*)')

while not interrupted:
    try:
        line = sys.stdin.readline()
        if not line:
            break

        m = reg.match(line)

        if not m: print >> sys.stderr, "Invalid input line."

        s = string.split(m.group(4))

        args = {'cpu'   : m.group(1),
                'tsc'   : m.group(2),
                'event' : m.group(3) }

        i = 0
        for item in s:
            args[str(i)] = item
            i += 1

        if defs.has_key(m.group(3)): print defs[m.group(3)] % args
        # silently skip lines we don't have a format for - a 'complain' option
        # should be added if needed

    except IOError: sys.exit()
