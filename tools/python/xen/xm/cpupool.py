#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2009 Fujitsu Technology Solutions
#============================================================================

""" Common function of cmds cpupool-new / cpupool-create.
"""

import sys
import types
import os

from xen.xend import PrettyPrint
from xen.xend import sxp

from xen.xm.opts import Opts, set_value, set_true, append_value, OptionError

GOPTS = Opts(use="""[options] [vars]

Create a cpupool.

Pool creation parameters can be set by command-line switches, from
a python configuration script or an SXP config file. See documentation
for --defconfig, --config. Configuration variables can be set using
VAR=VAL on the command line. For example name=Pool-1 sets name to Pool-1.

""")

GOPTS.opt('help', short='h',
          fn=set_true, default=0,
          use="Print this help.")

GOPTS.opt('help_config',
          fn=set_true, default=0,
          use="Print the available configuration variables (vars) for the "
          "configuration script.")

GOPTS.opt('path', val='PATH',
          fn=set_value, default='.:/etc/xen/cpupool',
          use="Search path for configuration scripts. "
          "The value of PATH is a colon-separated directory list.")

GOPTS.opt('defconfig', short='f', val='FILE',
          fn=set_value, default='xmdefconfig',
          use="Use the given Python configuration script."
          "The configuration script is loaded after arguments have been "
          "processed. Each command-line option sets a configuration "
          "variable named after its long option name, and these "
          "variables are placed in the environment of the script before "
          "it is loaded. Variables for options that may be repeated have "
          "list values. Other variables can be set using VAR=VAL on the "
          "command line. "
          "After the script is loaded, option values that were not set "
          "on the command line are replaced by the values set in the script.")

GOPTS.default('defconfig')

GOPTS.opt('config', short='F', val='FILE',
          fn=set_value, default=None,
          use="CPU pool configuration to use (SXP).\n"
          "SXP is the underlying configuration format used by Xen.\n"
          "SXP configurations can be hand-written or generated from Python "
          "configuration scripts, using the -n (dryrun) option to print "
          "the configuration.")

GOPTS.opt('dryrun', short='n',
          fn=set_true, default=0,
          use="Dry run - prints the resulting configuration in SXP but "
          "does not create the CPU pool.")

GOPTS.var('name', val='NAME', fn=set_value, default=None,
          use="CPU pool name.")

GOPTS.var('sched', val='SCHED', fn=set_value, default='credit',
          use="Scheduler to use for the CPU pool.")

GOPTS.var('cpus', val='CPUS', fn=set_value, default=1,
          use="CPUS to assign to the CPU pool.")

GOPTS.var('other_config', val='OTHER_CONFIG', fn=append_value, default=[],
          use="Additional info for CPU pool")


def sxp2map(sxp_val):
    record = {}
    for x in sxp_val:
        if isinstance(x, (types.ListType, types.TupleType)) \
           and len(x) > 1:
            if isinstance(x[1], (types.ListType, types.TupleType)):
                record[x[0]] = sxp2map(x[1])
            else:
                record[x[0]] = x[1]
    return record

def err(msg):
    print >> sys.stderr, "Error: %s" % msg
    sys.exit(-1)

def make_cpus_config(cfg_cpus):
    """ Taken from XendConfig. """
    # Convert 'cpus' to list of list of ints

    cpus_list = []
    # Convert the following string to list of ints.
    # The string supports a list of ranges (0-3),
    # seperated by commas, and negation (^1).
    # Precedence is settled by order of the string:
    #    "0-3,^1"      -> [0,2,3]
    #    "0-3,^1,1"    -> [0,1,2,3]
    def cnv(s):
        l = []
        for c in s.split(','):
            if c.find('-') != -1:
                (x, y) = c.split('-')
                for i in range(int(x), int(y)+1):
                    l.append(int(i))
            else:
                # remove this element from the list
                if len(c) > 0:
                    if c[0] == '^':
                        l = [x for x in l if x != int(c[1:])]
                    else:
                        l.append(int(c))
        return l

    if type(cfg_cpus) == list:
        if len(cfg_cpus) > 0 and type(cfg_cpus[0]) == list:
            # If sxp_cfg was created from config.sxp,
            # the form of 'cpus' is list of list of string.
            # Convert 'cpus' to list of list of ints.
            # Conversion examples:
            #    [['1']]               -> [[1]]
            #    [['0','2'],['1','3']] -> [[0,2],[1,3]]
            try:
                for c1 in cfg_cpus:
                    cpus = []
                    for c2 in c1:
                        cpus.append(int(c2))
                    cpus_list.append(cpus)
            except ValueError, e:
                raise err('cpus = %s: %s' % (cfg_cpus, e))
        else:
            # Conversion examples:
            #    ["1"]               -> [[1]]
            #    ["0,2","1,3"]       -> [[0,2],[1,3]]
            #    ["0-3,^1","1-4,^2"] -> [[0,2,3],[1,3,4]]
            try:
                for c in cfg_cpus:
                    cpus = cnv(c)
                    cpus_list.append(cpus)
            except ValueError, e:
                raise err('cpus = %s: %s' % (cfg_cpus, e))
    else:
        # Conversion examples:
        #  cpus=1:
        #    "1"      -> [[1]]
        #    "0-3,^1" -> [[0,2,3]]
        #  cpus=2:
        #    "1"      -> [[1],[1]]
        #    "0-3,^1" -> [[0,2,3],[0,2,3]]
        try:
            cpus_list = cnv(cfg_cpus)
        except ValueError, e:
            err('cpus = %s: %s' % (cfg_cpus, e))
    return cpus_list

def make_config(vals):
    config  = ['pool']
    config += [['name_label', vals.name]]
    config += [['sched_policy', vals.sched]]
    if type(vals.cpus) == int:
        config +=  [['ncpu', vals.cpus], ['proposed_CPUs' , []]]
    elif type(vals.cpus) == str and len(vals.cpus) > 1 and vals.cpus[0] == '#':
        try:
            config +=  [['ncpu', int(vals.cpus[1:])], ['proposed_CPUs' , []]]
        except ValueError, ex:
            err('Wrong illegal of parameter "cpus"')
    else:
        prop_cpus = make_cpus_config(vals.cpus)
        config +=  [['ncpu', len(prop_cpus)],
                    ['proposed_CPUs'] + prop_cpus]
    other_config = []
    for entry in vals.other_config:
        if '=' in entry:
            (var, val) = entry.strip().split('=', 1)
            other_config.append([var, val])
    config +=  [['other_config'] + other_config]
    return config

def parseCommandLine(argv):
    GOPTS.reset()
    args = GOPTS.parse(argv)

    if GOPTS.vals.help or GOPTS.vals.help_config:
        if GOPTS.vals.help_config:
            print GOPTS.val_usage()
        return (None, None)

    # Process remaining args as config variables.
    for arg in args:
        if '=' in arg:
            (var, val) = arg.strip().split('=', 1)
            GOPTS.setvar(var.strip(), val.strip())
    if GOPTS.vals.config:
        try:
            config = sxp.parse(file(GOPTS.vals.config))[0]
        except IOError, ex:
            raise OptionError("Cannot read file %s: %s" % (config, ex[1]))
    else:
        GOPTS.load_defconfig()
        if not GOPTS.getopt('name') and GOPTS.getopt('defconfig'):
            GOPTS.setopt('name', os.path.basename(
                GOPTS.getopt('defconfig')))
        config = make_config(GOPTS.vals)

    if GOPTS.vals.dryrun:
        PrettyPrint.prettyprint(config)
        return (None, None)

    return (GOPTS, config)

def help():
    return str(GOPTS)

