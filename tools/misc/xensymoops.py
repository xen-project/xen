#!/usr/bin/env python

# An oops analyser for Xen
# Usage: xensymoops path-to-xen.s < oops-message

# There's probably some more features that could go in here but this
# is sufficient to analyse most errors in my code ;-)

# by Mark Williamson (C) 2004 Intel Research Cambridge

import re, sys

def read_oops():
    """Process an oops message on stdin and return (eip_addr, stack_addrs)

    eip_addr is the location of EIP at the point of the crash.
    stack_addrs is a dictionary mapping potential code addresses in the stack
      to their order in the stack trace.
    """
    stackaddr_ptn = "\[([a-z,0-9]*)\]"
    stackaddr_re  = re.compile(stackaddr_ptn)

    eip_ptn = ".*EIP:.*<([a-z,0-9]*)>.*"
    eip_re  = re.compile(eip_ptn)

    matches = 0
    stack_addresses = {}
    eip_addr = "Not known"

    while True:
        line = sys.stdin.readline()
        if not line: break

        m = eip_re.match(line)
        if m: eip_addr = m.group(1)
        
        m = stackaddr_re.findall(line)
    
        for i in m:
            stack_addresses[i] = matches
            matches += 1

    return (eip_addr, stack_addresses)

def usage():
    print >> sys.stderr, """Usage: %s path-to-asm < oops-msg
    The oops message should be fed to the standard input.  The
    command-line argument specifies the path to the Xen assembly dump
    produced by \"make debug\".  The location of EIP and the backtrace
    will be output to standard output.
    """ % sys.argv[0]
    sys.exit()

##### main

if len(sys.argv) != 2:
    usage()

# get address of EIP and the potential code addresses from the stack
(eip_addr, stk_addrs) = read_oops()

# open Xen disassembly
asm_file = open(sys.argv[1])

# regexp to match addresses of code lines in the objdump
addr_ptn = "([a-z,0-9]*):"
addr_re  = re.compile(addr_ptn)

# regexp to match the start of functions in the objdump
func_ptn = "(.*<[\S]*>):"
func_re  = re.compile(func_ptn)

func = "<No function>" # holds the name of the current function being scanned

eip_func = "<No function>" # name of the function EIP was in

# list of (position in original backtrace, code address, function) tuples
# describing all the potential code addresses we identified in the backtrace
# whose addresses we also located in the objdump output
backtrace = []

while True:
    line = asm_file.readline()
    if not line: break

    # if we've read the start of the function, record the name and address
    fm = func_re.match(line)
    if fm:
        func = fm.group(1)
        continue

    # try match the address at the start of the line
    m = addr_re.match(line)
    if not m: continue

    # we're on a code line...

    address = m.group(1)

    # if this address was seen as a potential code address in the backtrace then
    # record it in the backtrace list
    if stk_addrs.has_key(address):
        backtrace.append((stk_addrs[address], address, func))

    # if this was the address that EIP...
    if address == eip_addr:
        eip_func = func


print "EIP %s in function %s" % (eip_addr, eip_func)
print "Backtrace:"

# sorting will order primarily by the first element of each tuple,
# i.e. the order in the original oops
backtrace.sort()

for (i, a, f) in backtrace:
    print "%s in function %s" % ( a, f )
