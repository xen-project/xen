#!/usr/bin/env python

# by Mark Williamson, (C) 2004 Intel Research Cambridge

# Program for separating trace buffer data into per-cpu log files.

import re, sys, signal

def usage():
    print >> sys.stderr, \
          "Usage: " + sys.argv[0] + """ base-name
          Separates ASCII trace buffer data on stdin into per-CPU trace
          files.  The trace files are named by appending the CPU number
          to the base name supplied on the command line.

          Depending on your system and the volume of trace buffer data,
          this script may not be able to keep up with the output of xentrace
          if it is piped directly.  In these circumstances you should have
          xentrace output to a file for processing off-line.
          """
    sys.exit(1)
    
def sighand(x,y):
    global interrupted
    interrupted = 1

signal.signal(signal.SIGTERM, sighand)
signal.signal(signal.SIGHUP,  sighand)
signal.signal(signal.SIGINT,  sighand)

r = re.compile("(\d) .*")

if len(sys.argv) < 2:
    usage()
else:
    base_name = sys.argv[1]

files = {}
interrupted = 0

while not interrupted:
    try:
        line = sys.stdin.readline()
        if not line: break
        
        m = r.match(line)

        if not m: print >> sys.stderr, "Invalid input line."
        
        cpu = m.group(1)
        
        if not files.has_key(base_name + str(cpu)):
            files[base_name + str(cpu)] = open(base_name + str(cpu), "w")
            
        print >> files[base_name + str(cpu)], line,

    except IOError: sys.exit()

# files closed automatically
