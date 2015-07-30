#!/usr/bin/env python

#####################################################################
# xenmon is a front-end for xenbaked.
# There is a curses interface for live monitoring. XenMon also allows
# logging to a file. For options, run python xenmon.py -h
#
# Copyright (C) 2005,2006 by Hewlett Packard, Palo Alto and Fort Collins
# Authors: Lucy Cherkasova, lucy.cherkasova@hp.com
#          Rob Gardner, rob.gardner@hp.com
#          Diwaker Gupta, diwaker.gupta@hp.com
#####################################################################
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; under version 2 of the License.
# 
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with this program; If not, see <http://www.gnu.org/licenses/>.
#####################################################################

import mmap
import struct
import os
import time
import optparse as _o
import curses as _c
import math
import sys

# constants
NSAMPLES = 100
NDOMAINS = 32
IDLE_DOMAIN = -1 # idle domain's ID

# the struct strings for qos_info
ST_DOM_INFO = "6Q3i2H32s"
ST_QDATA = "%dQ" % (6*NDOMAINS + 4)

# size of mmaped file
QOS_DATA_SIZE = struct.calcsize(ST_QDATA)*NSAMPLES + struct.calcsize(ST_DOM_INFO)*NDOMAINS + struct.calcsize("4i")

# location of mmaped file, hard coded right now
SHM_FILE = "/var/run/xenq-shm"

# format strings
TOTALS = 15*' ' + "%6.2f%%" + 35*' ' + "%6.2f%%"

ALLOCATED = "Allocated"
GOTTEN = "Gotten"
BLOCKED = "Blocked"
WAITED = "Waited"
IOCOUNT = "I/O Count"
EXCOUNT = "Exec Count"

# globals
dom_in_use = []

# our curses screen
stdscr = None

# parsed options
options, args = None, None

# the optparse module is quite smart
# to see help, just run xenmon -h
def setup_cmdline_parser():
    parser = _o.OptionParser()
    parser.add_option("-l", "--live", dest="live", action="store_true",
                      default=True, help = "show the ncurses live monitoring frontend (default)")
    parser.add_option("-n", "--notlive", dest="live", action="store_false",
                      default="True", help = "write to file instead of live monitoring")
    parser.add_option("-p", "--prefix", dest="prefix",
                      default = "log", help="prefix to use for output files")
    parser.add_option("-t", "--time", dest="duration",
            action="store", type="int", default=10, 
            help="stop logging to file after this much time has elapsed (in seconds). set to 0 to keep logging indefinitely")
    parser.add_option("-i", "--interval", dest="interval",
            action="store", type="int", default=1000,
            help="interval for logging (in ms)")
    parser.add_option("--ms_per_sample", dest="mspersample",
            action="store", type="int", default=100,
            help = "determines how many ms worth of data goes in a sample")
    parser.add_option("--cpu", dest="cpu", action="store", type="int", default=0,
            help = "specifies which cpu to display data for")

    parser.add_option("--allocated", dest="allocated", action="store_true",
                      default=False, help="Display allocated time for each domain")
    parser.add_option("--noallocated", dest="allocated", action="store_false",
                      default=False, help="Don't display allocated time for each domain")

    parser.add_option("--blocked", dest="blocked", action="store_true",
                      default=True, help="Display blocked time for each domain")
    parser.add_option("--noblocked", dest="blocked", action="store_false",
                      default=True, help="Don't display blocked time for each domain")

    parser.add_option("--waited", dest="waited", action="store_true",
                      default=True, help="Display waiting time for each domain")
    parser.add_option("--nowaited", dest="waited", action="store_false",
                      default=True, help="Don't display waiting time for each domain")

    parser.add_option("--excount", dest="excount", action="store_true",
                      default=False, help="Display execution count for each domain")
    parser.add_option("--noexcount", dest="excount", action="store_false",
                      default=False, help="Don't display execution count for each domain")
    parser.add_option("--iocount", dest="iocount", action="store_true",
                      default=False, help="Display I/O count for each domain")
    parser.add_option("--noiocount", dest="iocount", action="store_false",
                      default=False, help="Don't display I/O count for each domain")

    return parser

# encapsulate information about a domain
class DomainInfo:
    def __init__(self):
        self.allocated_sum = 0
        self.gotten_sum = 0
        self.blocked_sum = 0
        self.waited_sum = 0
        self.exec_count = 0;
        self.iocount_sum = 0
        self.ffp_samples = []

    def gotten_stats(self, passed):
        total = float(self.gotten_sum)
        per = 100*total/passed
        exs = self.exec_count
        if exs > 0:
            avg = total/exs
        else:
            avg = 0
        return [total/(float(passed)/10**9), per, avg]

    def waited_stats(self, passed):
        total = float(self.waited_sum)
        per = 100*total/passed
        exs = self.exec_count
        if exs > 0:
            avg = total/exs
        else:
            avg = 0
        return [total/(float(passed)/10**9), per, avg]

    def blocked_stats(self, passed):
        total = float(self.blocked_sum)
        per = 100*total/passed
        ios = self.iocount_sum
        if ios > 0:
            avg = total/float(ios)
        else:
            avg = 0
        return [total/(float(passed)/10**9), per, avg]

    def allocated_stats(self, passed):
        total = self.allocated_sum
        exs = self.exec_count
        if exs > 0:
            return float(total)/exs
        else:
            return 0

    def ec_stats(self, passed):
        total = float(self.exec_count/(float(passed)/10**9))
        return total

    def io_stats(self, passed):
        total = float(self.iocount_sum)
        exs = self.exec_count
        if exs > 0:
            avg = total/exs
        else:
            avg = 0
        return [total/(float(passed)/10**9), avg]

    def stats(self, passed):
        return [self.gotten_stats(passed), self.allocated_stats(passed), self.blocked_stats(passed), 
                self.waited_stats(passed), self.ec_stats(passed), self.io_stats(passed)]

# report values over desired interval
def summarize(startat, endat, duration, samples):
    dominfos = {}
    for i in range(0, NDOMAINS):
        dominfos[i] = DomainInfo()
        
    passed = 1              # to prevent zero division
    curid = startat
    numbuckets = 0
    lost_samples = []
    ffp_samples = []
    
    while passed < duration:
        for i in range(0, NDOMAINS):
            if dom_in_use[i]:
                dominfos[i].gotten_sum += samples[curid][0*NDOMAINS + i]
                dominfos[i].allocated_sum += samples[curid][1*NDOMAINS + i]
                dominfos[i].waited_sum += samples[curid][2*NDOMAINS + i]
                dominfos[i].blocked_sum += samples[curid][3*NDOMAINS + i]
                dominfos[i].exec_count += samples[curid][4*NDOMAINS + i]
                dominfos[i].iocount_sum += samples[curid][5*NDOMAINS + i]
    
        passed += samples[curid][6*NDOMAINS]
        lost_samples.append(samples[curid][6*NDOMAINS + 2])
        ffp_samples.append(samples[curid][6*NDOMAINS + 3])

        numbuckets += 1

        if curid > 0:
            curid -= 1
        else:
            curid = NSAMPLES - 1
        if curid == endat:
            break

    lostinfo = [min(lost_samples), sum(lost_samples), max(lost_samples)]
    ffpinfo = [min(ffp_samples), sum(ffp_samples), max(ffp_samples)]

    ldoms = []
    for x in range(0, NDOMAINS):
        if dom_in_use[x]:
            ldoms.append(dominfos[x].stats(passed))
        else:
            ldoms.append(0)

    return [ldoms, lostinfo, ffpinfo]

# scale microseconds to milliseconds or seconds as necessary
def time_scale(ns):
    if ns < 1000:
        return "%4.2f ns" % float(ns)
    elif ns < 1000*1000:
        return "%4.2f us" % (float(ns)/10**3)
    elif ns < 10**9:
        return "%4.2f ms" % (float(ns)/10**6)
    else:
        return "%4.2f s" % (float(ns)/10**9)

# paint message on curses screen, but detect screen size errors
def display(scr, row, col, str, attr=0):
    try:
        scr.addstr(row, col, str, attr)
    except:
        scr.erase()
        _c.nocbreak()
        scr.keypad(0)
        _c.echo()
        _c.endwin()
        print "Your terminal screen is not big enough; Please resize it."
        print "row=%d, col=%d, str='%s'" % (row, col, str)
        sys.exit(1)


# diplay domain id
def display_domain_id(scr, row, col, dom):
    if dom == IDLE_DOMAIN:
        display(scr, row, col-1, "Idle")
    else:
        display(scr, row, col, "%d" % dom)


# the live monitoring code
def show_livestats(cpu):
    ncpu = 1         # number of cpu's on this platform
    slen = 0         # size of shared data structure, incuding padding
    cpu_1sec_usage = 0.0
    cpu_10sec_usage = 0.0
    heartbeat = 1
    global dom_in_use, options
    
    # mmap the (the first chunk of the) file
    shmf = open(SHM_FILE, "r+")
    shm = mmap.mmap(shmf.fileno(), QOS_DATA_SIZE)

    # initialize curses
    stdscr = _c.initscr()
    _c.noecho()
    _c.cbreak()

    stdscr.keypad(1)
    stdscr.timeout(1000)
    [maxy, maxx] = stdscr.getmaxyx()
    
    # display in a loop
    while True:

        cpuidx = 0
        while cpuidx < ncpu:

            # calculate offset in mmap file to start from
            idx = cpuidx * slen


            samples = []
            doms = []
            dom_in_use = []
            domain_id = []

            # read in data
            for i in range(0, NSAMPLES):
                len = struct.calcsize(ST_QDATA)
                sample = struct.unpack(ST_QDATA, shm[idx:idx+len])
                samples.append(sample)
                idx += len

            for i in range(0, NDOMAINS):
                len = struct.calcsize(ST_DOM_INFO)
                dom = struct.unpack(ST_DOM_INFO, shm[idx:idx+len])
                doms.append(dom)
#               (last_update_time, start_time, runnable_start_time, blocked_start_time,
#                ns_since_boot, ns_oncpu_since_boot, runnable_at_last_update,
#                runnable, in_use, domid, junk, name) = dom
#               dom_in_use.append(in_use)
                dom_in_use.append(dom[8])
                domid = dom[9]
                if domid == 32767 :
                    domid = IDLE_DOMAIN
                domain_id.append(domid)
                idx += len
#            print "dom_in_use(cpu=%d): " % cpuidx, dom_in_use


            len = struct.calcsize("4i")
            oldncpu = ncpu
            (next, ncpu, slen, freq) = struct.unpack("4i", shm[idx:idx+len])
            idx += len

            # xenbaked tells us how many cpu's it's got, so re-do
            # the mmap if necessary to get multiple cpu data
            if oldncpu != ncpu:
                shm = mmap.mmap(shmf.fileno(), ncpu*slen)

            # if we've just calculated data for the cpu of interest, then
            # stop examining mmap data and start displaying stuff
            if cpuidx == cpu:
                break

            cpuidx = cpuidx + 1

        # calculate starting and ending datapoints; never look at "next" since
        # it represents live data that may be in transition. 
        startat = next - 1
        if next + 10 < NSAMPLES:
            endat = next + 10
        else:
            endat = 10

        # get summary over desired interval
        [h1, l1, f1] = summarize(startat, endat, 10**9, samples)
        [h2, l2, f2] = summarize(startat, endat, 10 * 10**9, samples)


        # the actual display code
        row = 0
        display(stdscr, row, 1, "CPU = %d" % cpu, _c.A_STANDOUT)

        display(stdscr, row, 10, "%sLast 10 seconds (%3.2f%%)%sLast 1 second (%3.2f%%)" % (6*' ', cpu_10sec_usage, 30*' ', cpu_1sec_usage), _c.A_BOLD)
        row +=1
        display(stdscr, row, 1, "%s" % ((maxx-2)*'='))

        total_h1_cpu = 0
        total_h2_cpu = 0

        cpu_1sec_usage = 0.0
        cpu_10sec_usage = 0.0

        for dom in range(0, NDOMAINS):
            if not dom_in_use[dom]:
                continue

            if h1[dom][0][1] > 0 or domain_id[dom] == IDLE_DOMAIN:
                # display gotten
                row += 1 
                col = 2
                display_domain_id(stdscr, row, col, domain_id[dom])
                col += 4
                display(stdscr, row, col, "%s" % time_scale(h2[dom][0][0]))
                col += 12
                display(stdscr, row, col, "%3.2f%%" % h2[dom][0][1])
                if dom != IDLE_DOMAIN:
                    cpu_10sec_usage += h2[dom][0][1]
                col += 12
                display(stdscr, row, col, "%s/ex" % time_scale(h2[dom][0][2]))
                col += 18
                display(stdscr, row, col, "%s" % time_scale(h1[dom][0][0]))
                col += 12
                display(stdscr, row, col, "%3.2f%%" % h1[dom][0][1], _c.A_STANDOUT)
                col += 12
                display(stdscr, row, col, "%s/ex" % time_scale(h1[dom][0][2]))
                col += 18
                display(stdscr, row, col, "Gotten")

                if dom != IDLE_DOMAIN:
                    cpu_1sec_usage = cpu_1sec_usage + h1[dom][0][1]
    
                # display allocated
                if options.allocated:
                    row += 1
                    col = 2
                    display_domain_id(stdscr, row, col, domain_id[dom])
                    col += 28
                    display(stdscr, row, col, "%s/ex" % time_scale(h2[dom][1]))
                    col += 42
                    display(stdscr, row, col, "%s/ex" % time_scale(h1[dom][1]))
                    col += 18
                    display(stdscr, row, col, "Allocated")

                # display blocked
                if options.blocked:
                    row += 1
                    col = 2
                    display_domain_id(stdscr, row, col, domain_id[dom])
                    col += 4
                    display(stdscr, row, col, "%s" % time_scale(h2[dom][2][0]))
                    col += 12
                    display(stdscr, row, col, "%3.2f%%" % h2[dom][2][1])
                    col += 12
                    display(stdscr, row, col, "%s/io" % time_scale(h2[dom][2][2]))
                    col += 18
                    display(stdscr, row, col, "%s" % time_scale(h1[dom][2][0]))
                    col += 12
                    display(stdscr, row, col, "%3.2f%%" % h1[dom][2][1])
                    col += 12
                    display(stdscr, row, col, "%s/io" % time_scale(h1[dom][2][2]))
                    col += 18
                    display(stdscr, row, col, "Blocked")

                # display waited
                if options.waited:
                    row += 1
                    col = 2
                    display_domain_id(stdscr, row, col, domain_id[dom])
                    col += 4
                    display(stdscr, row, col, "%s" % time_scale(h2[dom][3][0]))
                    col += 12
                    display(stdscr, row, col, "%3.2f%%" % h2[dom][3][1])
                    col += 12
                    display(stdscr, row, col, "%s/ex" % time_scale(h2[dom][3][2]))
                    col += 18
                    display(stdscr, row, col, "%s" % time_scale(h1[dom][3][0]))
                    col += 12
                    display(stdscr, row, col, "%3.2f%%" % h1[dom][3][1])
                    col += 12
                    display(stdscr, row, col, "%s/ex" % time_scale(h1[dom][3][2]))
                    col += 18
                    display(stdscr, row, col, "Waited")

                # display ex count
                if options.excount:
                    row += 1
                    col = 2
                    display_domain_id(stdscr, row, col, domain_id[dom])
                    
                    col += 28
                    display(stdscr, row, col, "%d/s" % h2[dom][4])
                    col += 42
                    display(stdscr, row, col, "%d" % h1[dom][4])
                    col += 18
                    display(stdscr, row, col, "Execution count")

                # display io count
                if options.iocount:
                    row += 1
                    col = 2
                    display_domain_id(stdscr, row, col, domain_id[dom])
                    col += 4
                    display(stdscr, row, col, "%d/s" % h2[dom][5][0])
                    col += 24
                    display(stdscr, row, col, "%d/ex" % h2[dom][5][1])
                    col += 18
                    display(stdscr, row, col, "%d" % h1[dom][5][0])
                    col += 24
                    display(stdscr, row, col, "%3.2f/ex" % h1[dom][5][1])
                    col += 18
                    display(stdscr, row, col, "I/O Count")

            #row += 1
            #stdscr.hline(row, 1, '-', maxx - 2)
            total_h1_cpu += h1[dom][0][1]
            total_h2_cpu += h2[dom][0][1]


        row += 1
        star = heartbeat * '*'
        heartbeat = 1 - heartbeat
        display(stdscr, row, 1, star)
        display(stdscr, row, 2, TOTALS % (total_h2_cpu, total_h1_cpu))
        row += 1
#        display(stdscr, row, 2, 
#                "\tFFP: %d (Min: %d, Max: %d)\t\t\tFFP: %d (Min: %d, Max %d)" % 
#                (math.ceil(f2[1]), f2[0], f2[2], math.ceil(f1[1]), f1[0], f1[2]), _c.A_BOLD)

        if l1[1] > 1 :
            row += 1
            display(stdscr, row, 2, 
                    "\tRecords lost: %d (Min: %d, Max: %d)\t\t\tRecords lost: %d (Min: %d, Max %d)" % 
                    (math.ceil(l2[1]), l2[0], l2[2], math.ceil(l1[1]), l1[0], l1[2]), _c.A_BOLD)

        # grab a char from tty input; exit if interrupt hit
        try:
            c = stdscr.getch()
        except:
            break
        
        # q = quit
        if c == ord('q'):
            break
    
        # c = cycle to a new cpu of interest
        if c == ord('c'):
            cpu = (cpu + 1) % ncpu

        # n/p = cycle to the next/previous CPU
        if c == ord('n'):
            cpu = (cpu + 1) % ncpu
        if c == ord('p'):
            cpu = (cpu - 1) % ncpu

        stdscr.erase()

    _c.nocbreak()
    stdscr.keypad(0)
    _c.echo()
    _c.endwin()
    shm.close()
    shmf.close()


# simple functions to allow initialization of log files without actually
# physically creating files that are never used; only on the first real
# write does the file get created
class Delayed(file):
    def __init__(self, filename, mode):
        self.filename = filename
        self.saved_mode = mode
        self.delay_data = ""
        self.opened = 0

    def delayed_write(self, str):
        self.delay_data = str

    def write(self, str):
        if not self.opened:
            self.file = open(self.filename, self.saved_mode)
            self.opened = 1
            self.file.write(self.delay_data)
        self.file.write(str)

    def rename(self, name):
        self.filename = name

    def flush(self):
        if  self.opened:
            self.file.flush()

    def close(self):
        if  self.opened:
            self.file.close()
            

def writelog():
    global options
    global dom_in_use

    ncpu = 1        # number of cpu's
    slen = 0        # size of shared structure inc. padding

    shmf = open(SHM_FILE, "r+")
    shm = mmap.mmap(shmf.fileno(), QOS_DATA_SIZE)

    interval = 0
    curr = last = time.time()
    outfiles = {}
    for dom in range(0, NDOMAINS):
        outfiles[dom] = Delayed("%s-dom%d.log" % (options.prefix, dom), 'w')
        outfiles[dom].delayed_write("# passed cpu dom cpu(tot) cpu(%) cpu/ex allocated/ex blocked(tot) blocked(%) blocked/io waited(tot) waited(%) waited/ex ex/s io(tot) io/ex\n")

    while options.duration == 0 or interval < (options.duration * 1000):
        cpuidx = 0
        while cpuidx < ncpu:

            idx = cpuidx * slen      # offset needed in mmap file

            samples = []
            doms = []
            dom_in_use = []
            domain_id = []

            for i in range(0, NSAMPLES):
                len = struct.calcsize(ST_QDATA)
                sample = struct.unpack(ST_QDATA, shm[idx:idx+len])
                samples.append(sample)
                idx += len

            for i in range(0, NDOMAINS):
                len = struct.calcsize(ST_DOM_INFO)
                dom = struct.unpack(ST_DOM_INFO, shm[idx:idx+len])
#                doms.append(dom)
#               (last_update_time, start_time, runnable_start_time, blocked_start_time,
#                ns_since_boot, ns_oncpu_since_boot, runnable_at_last_update,
#                runnable, in_use, domid, junk, name) = dom
                dom_in_use.append(dom[8])
                domid = dom[9]
                if domid == 32767:
                    domid = IDLE_DOMAIN
                domain_id.append(domid)
                if domid == IDLE_DOMAIN:
                    outfiles[i].rename("%s-idle.log" % options.prefix)
                else:
                    outfiles[i].rename("%s-dom%d.log" % (options.prefix, domid))
                idx += len

            len = struct.calcsize("4i")
            oldncpu = ncpu
            (next, ncpu, slen, freq) = struct.unpack("4i", shm[idx:idx+len])
            idx += len

            if oldncpu != ncpu:
                shm = mmap.mmap(shmf.fileno(), ncpu*slen)

            startat = next - 1
            if next + 10 < NSAMPLES:
                endat = next + 10
            else:
                endat = 10

            [h1,l1, f1] = summarize(startat, endat, options.interval * 10**6, samples)
            for dom in range(0, NDOMAINS):
                if not dom_in_use[dom]:
                    continue
                if h1[dom][0][1] > 0 or dom == IDLE_DOMAIN:
                    outfiles[dom].write("%.3f %d %d %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f %.3f\n" %
                                     (interval, cpuidx, domain_id[dom],
                                     h1[dom][0][0], h1[dom][0][1], h1[dom][0][2],
                                     h1[dom][1],
                                     h1[dom][2][0], h1[dom][2][1], h1[dom][2][2],
                                     h1[dom][3][0], h1[dom][3][1], h1[dom][3][2],
                                     h1[dom][4], 
                                     h1[dom][5][0], h1[dom][5][1]))
                    outfiles[dom].flush()
            curr = time.time()
            interval += (curr - last) * 1000
            last = curr
            cpuidx = cpuidx + 1
        time.sleep(options.interval / 1000.0)

    for dom in range(0, NDOMAINS):
        outfiles[dom].close()

# start xenbaked
def start_xenbaked():
    global options
    global kill_cmd
    global xenbaked_cmd

    os.system(kill_cmd)
    os.system(xenbaked_cmd + " --ms_per_sample=%d &" %
              options.mspersample)
    time.sleep(1)

# stop xenbaked
def stop_xenbaked():
    global stop_cmd
    os.system(stop_cmd)

def main():
    global options
    global args
    global domains
    global stop_cmd
    global kill_cmd
    global xenbaked_cmd

    if os.uname()[0] == "SunOS":
        xenbaked_cmd = "/usr/lib/xenbaked"
	stop_cmd = "/usr/bin/pkill -INT -z global xenbaked"
	kill_cmd = "/usr/bin/pkill -KILL -z global xenbaked"
    else:
        # assumes that xenbaked is in your path
        xenbaked_cmd = "xenbaked"
        stop_cmd = "/usr/bin/pkill -INT xenbaked"
        kill_cmd = "/usr/bin/pkill -KILL xenbaked"

    parser = setup_cmdline_parser()
    (options, args) = parser.parse_args()

    if len(args):
        parser.error("No parameter required")
    if options.mspersample < 0:
        parser.error("option --ms_per_sample: invalid negative value: '%d'" %
                     options.mspersample)
    # If --ms_per_sample= is too large, no data may be logged.
    if not options.live and options.duration != 0 and \
       options.mspersample > options.duration * 1000:
        parser.error("option --ms_per_sample: too large (> %d ms)" %
                     (options.duration * 1000))
    
    start_xenbaked()
    if options.live:
        show_livestats(options.cpu)
    else:
        try:
            writelog()
        except:
            print 'Quitting.'
    stop_xenbaked()

if __name__ == "__main__":
    main()
