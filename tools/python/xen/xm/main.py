# (C) Copyright IBM Corp. 2005
# Copyright (C) 2004 Mike Wray
# Copyright (c) 2005-2006 XenSource Ltd.
#
# Authors:
#     Sean Dague <sean at dague dot net>
#     Mike Wray <mike dot wray at hp dot com>
#
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

"""Grand unified management application for Xen.
"""
import atexit
import cmd
import os
import pprint
import readline
import shlex
import sys
import re
import getopt
import socket
import traceback
import xmlrpclib
import time
import datetime
from select import select
import xml.dom.minidom
from xen.util.blkif import blkdev_name_to_number

import warnings
warnings.filterwarnings('ignore', category=FutureWarning)

from xen.xend import PrettyPrint
from xen.xend import sxp
from xen.xend import XendClient
from xen.xend.XendConstants import *

from xen.xm.opts import OptionError, Opts, wrap, set_true
from xen.xm import console
from xen.util.xmlrpcclient import ServerProxy

import XenAPI


# getopt.gnu_getopt is better, but only exists in Python 2.3+.  Use
# getopt.getopt if gnu_getopt is not available.  This will mean that options
# may only be specified before positional arguments.
if not hasattr(getopt, 'gnu_getopt'):
    getopt.gnu_getopt = getopt.getopt

XM_CONFIG_FILE_ENVVAR = 'XM_CONFIG_FILE'
XM_CONFIG_FILE_DEFAULT = '/etc/xen/xm-config.xml'

# Supported types of server
SERVER_LEGACY_XMLRPC = 'LegacyXMLRPC'
SERVER_XEN_API = 'Xen-API'

# General help message

USAGE_HELP = "Usage: xm <subcommand> [args]\n\n" \
             "Control, list, and manipulate Xen guest instances.\n"

USAGE_FOOTER = '<Domain> can either be the Domain Name or Id.\n' \
               'For more help on \'xm\' see the xm(1) man page.\n' \
               'For more help on \'xm create\' see the xmdomain.cfg(5) '\
               ' man page.\n'

# Help strings are indexed by subcommand name in this way:
# 'subcommand': (argstring, description)

SUBCOMMAND_HELP = {
    # common commands

    'shell'       : ('', 'Launch an interactive shell.'),
    
    'console'     : ('[-q|--quiet] <Domain>',
                     'Attach to <Domain>\'s console.'),
    'create'      : ('<ConfigFile> [options] [vars]',
                     'Create a domain based on <ConfigFile>.'),
    'destroy'     : ('<Domain>',
                     'Terminate a domain immediately.'),
    'help'        : ('', 'Display this message.'),
    'list'        : ('[options] [Domain, ...]',
                     'List information about all/some domains.'),
    'mem-max'     : ('<Domain> <Mem>',
                     'Set the maximum amount reservation for a domain.'),
    'mem-set'     : ('<Domain> <Mem>',
                     'Set the current memory usage for a domain.'),
    'migrate'     : ('<Domain> <Host>',
                     'Migrate a domain to another machine.'),
    'pause'       : ('<Domain>', 'Pause execution of a domain.'),
    'reboot'      : ('<Domain> [-wa]', 'Reboot a domain.'),
    'restore'     : ('<CheckpointFile> [-p]',
                     'Restore a domain from a saved state.'),
    'save'        : ('[-c] <Domain> <CheckpointFile>',
                     'Save a domain state to restore later.'),
    'shutdown'    : ('<Domain> [-waRH]', 'Shutdown a domain.'),
    'top'         : ('', 'Monitor a host and the domains in real time.'),
    'unpause'     : ('<Domain>', 'Unpause a paused domain.'),
    'uptime'      : ('[-s] <Domain>', 'Print uptime for a domain.'),

    # Life cycle xm commands
    'new'         : ('<ConfigFile> [options] [vars]',
                     'Adds a domain to Xend domain management'),
    'delete'      : ('<DomainName>',
                     'Remove a domain from Xend domain management.'),
    'start'       : ('<DomainName>', 'Start a Xend managed domain'),
    'resume'      : ('<DomainName>', 'Resume a Xend managed domain'),
    'suspend'     : ('<DomainName>', 'Suspend a Xend managed domain'),

    # less used commands

    'dmesg'       : ('[-c|--clear]',
                     'Read and/or clear Xend\'s message buffer.'),
    'domid'       : ('<DomainName>', 'Convert a domain name to domain id.'),
    'domname'     : ('<DomId>', 'Convert a domain id to domain name.'),
    'dump-core'   : ('[-L|--live] [-C|--crash] <Domain> [Filename]',
                     'Dump core for a specific domain.'),
    'info'        : ('', 'Get information about Xen host.'),
    'log'         : ('', 'Print Xend log'),
    'rename'      : ('<Domain> <NewDomainName>', 'Rename a domain.'),
    'sched-sedf'  : ('<Domain> [options]', 'Get/set EDF parameters.'),
    'sched-credit': ('[-d <Domain> [-w[=WEIGHT]|-c[=CAP]]]',
                     'Get/set credit scheduler parameters.'),
    'sysrq'       : ('<Domain> <letter>', 'Send a sysrq to a domain.'),
    'debug-keys'  : ('<Keys>', 'Send debug keys to Xen.'),
    'trigger'     : ('<Domain> <nmi|reset|init> [<VCPU>]',
                     'Send a trigger to a domain.'),
    'vcpu-list'   : ('[<Domain>]',
                     'List the VCPUs for a domain or all domains.'),
    'vcpu-pin'    : ('<Domain> <VCPU> <CPUs|all>',
                     'Set which CPUs a VCPU can use.'),
    'vcpu-set'    : ('<Domain> <vCPUs>',
                     'Set the number of active VCPUs for allowed for the'
                     ' domain.'),

    # device commands

    'block-attach'  :  ('<Domain> <BackDev> <FrontDev> <Mode> [BackDomain]',
                        'Create a new virtual block device.'),
    'block-configure': ('<Domain> <BackDev> <FrontDev> <Mode> [BackDomain]',
                        'Change block device configuration'),
    'block-detach'  :  ('<Domain> <DevId> [-f|--force]',
                        'Destroy a domain\'s virtual block device.'),
    'block-list'    :  ('<Domain> [--long]',
                        'List virtual block devices for a domain.'),
    'network-attach':  ('<Domain> [type=<type>] [mac=<mac>] [bridge=<bridge>] '
                        '[ip=<ip>] [script=<script>] [backend=<BackDomain>] '
                        '[vifname=<name>] [rate=<rate>] [model=<model>]',
                        'Create a new virtual network device.'),
    'network-detach':  ('<Domain> <DevId> [-f|--force]',
                        'Destroy a domain\'s virtual network device.'),
    'network-list'  :  ('<Domain> [--long]',
                        'List virtual network interfaces for a domain.'),
    'vnet-create'   :  ('<ConfigFile>','Create a vnet from ConfigFile.'),
    'vnet-delete'   :  ('<VnetId>', 'Delete a Vnet.'),
    'vnet-list'     :  ('[-l|--long]', 'List Vnets.'),
    'vtpm-list'     :  ('<Domain> [--long]', 'List virtual TPM devices.'),

    # security

    'addlabel'      :  ('<label> {dom <ConfigFile>|res <resource>} [<policy>]',
                        'Add security label to domain.'),
    'rmlabel'       :  ('{dom <ConfigFile>|res <Resource>}',
                        'Remove a security label from domain.'),
    'getlabel'      :  ('{dom <ConfigFile>|res <Resource>}',
                        'Show security label for domain or resource.'),
    'dry-run'       :  ('<ConfigFile>',
                        'Test if a domain can access its resources.'),
    'resources'     :  ('', 'Show info for each labeled resource.'),
    'cfgbootpolicy' :  ('<policy> [boot-title]',
                        'Add policy to boot configuration.'),
    'dumppolicy'    :  ('', 'Print hypervisor ACM state information.'),
    'loadpolicy'    :  ('<policy.bin>', 'Load binary policy into hypervisor.'),
    'makepolicy'    :  ('<policy>', 'Build policy and create .bin/.map '
                        'files.'),
    'labels'        :  ('[policy] [type=dom|res|any]',
                        'List <type> labels for (active) policy.'),
    'serve'         :  ('', 'Proxy Xend XMLRPC over stdio.'),
}

SUBCOMMAND_OPTIONS = {
    'sched-sedf': (
       ('-p [MS]', '--period[=MS]', 'Relative deadline(ms)'),
       ('-s [MS]', '--slice[=MS]' ,
        'Worst-case execution time(ms). (slice < period)'),
       ('-l [MS]', '--latency[=MS]',
        'Scaled period (ms) when domain performs heavy I/O'),
       ('-e [FLAG]', '--extra[=FLAG]',
        'Flag (0 or 1) controls if domain can run in extra time.'),
       ('-w [FLOAT]', '--weight[=FLOAT]',
        'CPU Period/slice (do not set with --period/--slice)'),
    ),
    'sched-credit': (
       ('-d DOMAIN', '--domain=DOMAIN', 'Domain to modify'),
       ('-w WEIGHT', '--weight=WEIGHT', 'Weight (int)'),
       ('-c CAP',    '--cap=CAP',       'Cap (int)'),
    ),
    'list': (
       ('-l', '--long',         'Output all VM details in SXP'),
       ('', '--label',          'Include security labels'),
       ('', '--state=<state>',  'Select only VMs with the specified state'),
    ),
    'console': (
       ('-q', '--quiet', 'Do not print an error message if the domain does not exist'),
    ),
    'dmesg': (
       ('-c', '--clear', 'Clear dmesg buffer as well as printing it'),
    ),
    'vnet-list': (
       ('-l', '--long', 'List Vnets as SXP'),
    ),
    'network-list': (
       ('-l', '--long', 'List resources as SXP'),
    ),
    'dump-core': (
       ('-L', '--live', 'Dump core without pausing the domain'),
       ('-C', '--crash', 'Crash domain after dumping core'),
    ),
    'start': (
      ('-p', '--paused', 'Do not unpause domain after starting it'),
    ),
    'resume': (
      ('-p', '--paused', 'Do not unpause domain after resuming it'),
    ),
    'save': (
      ('-c', '--checkpoint', 'Leave domain running after creating snapshot'),
    ),
   'restore': (
      ('-p', '--paused', 'Do not unpause domain after restoring it'),
    ),
}

common_commands = [
    "console",
    "create",
    "new",
    "delete",
    "destroy",
    "dump-core",
    "help",
    "list",
    "mem-set",
    "migrate",
    "pause",
    "reboot",
    "restore",
    "resume",
    "save",
    "shell",
    "shutdown",
    "start",
    "suspend",
    "top",
    "unpause",
    "uptime",
    "vcpu-set",
    ]

domain_commands = [
    "console",
    "create",
    "new",
    "delete",
    "destroy",
    "domid",
    "domname",
    "dump-core",
    "list",
    "mem-max",
    "mem-set",
    "migrate",
    "pause",
    "reboot",
    "rename",
    "restore",
    "resume",
    "save",
    "shutdown",
    "start",
    "suspend",
    "sysrq",
    "trigger",
    "top",
    "unpause",
    "uptime",
    "vcpu-list",
    "vcpu-pin",
    "vcpu-set",
    ]

host_commands = [
    "debug-keys",
    "dmesg",
    "info",
    "log",
    "serve",
    ]

scheduler_commands = [
    "sched-credit",
    "sched-sedf",
    ]

device_commands = [
    "block-attach",
    "block-detach",
    "block-list",
    "block-configure",
    "network-attach",
    "network-detach",
    "network-list",
    "vtpm-list",
    ]

vnet_commands = [
    "vnet-list",
    "vnet-create",
    "vnet-delete",
    ]

acm_commands = [
    "labels",
    "addlabel",
    "rmlabel",
    "getlabel",
    "dry-run",
    "resources",
    "makepolicy",
    "loadpolicy",
    "cfgbootpolicy",
    "dumppolicy",
    ]

all_commands = (domain_commands + host_commands + scheduler_commands +
                device_commands + vnet_commands + acm_commands +
                ['shell', 'event-monitor'])


##
# Configuration File Parsing
##

xmConfigFile = os.getenv(XM_CONFIG_FILE_ENVVAR, XM_CONFIG_FILE_DEFAULT)
config = None
if os.path.isfile(xmConfigFile):
    try:
        config = xml.dom.minidom.parse(xmConfigFile)
    except:
        print >>sys.stderr, ('Ignoring invalid configuration file %s.' %
                             xmConfigFile)

def parseServer():
    if config:
        server = config.getElementsByTagName('server')
        if server:
            st = server[0].getAttribute('type')
            if st != SERVER_XEN_API and st != SERVER_LEGACY_XMLRPC:
                print >>sys.stderr, ('Invalid server type %s; using %s.' %
                                     (st, SERVER_LEGACY_XMLRPC))
                st = SERVER_LEGACY_XMLRPC
            return (st, server[0].getAttribute('uri'))

    return SERVER_LEGACY_XMLRPC, XendClient.uri

def parseAuthentication():
    server = config.getElementsByTagName('server')[0]
    return (server.getAttribute('username'),
            server.getAttribute('password'))

serverType, serverURI = parseServer()
server = None


####################################################################
#
#  Help/usage printing functions
#
####################################################################

def cmdHelp(cmd):
    """Print help for a specific subcommand."""
    
    for fc in SUBCOMMAND_HELP.keys():
        if fc[:len(cmd)] == cmd:
            cmd = fc
            break
    
    try:
        args, desc = SUBCOMMAND_HELP[cmd]
    except KeyError:
        shortHelp()
        return
    
    print 'Usage: xm %s %s' % (cmd, args)
    print
    print desc
    
    try:
        # If options help message is defined, print this.
        for shortopt, longopt, desc in SUBCOMMAND_OPTIONS[cmd]:
            if shortopt and longopt:
                optdesc = '%s, %s' % (shortopt, longopt)
            elif shortopt:
                optdesc = shortopt
            elif longopt:
                optdesc = longopt

            wrapped_desc = wrap(desc, 43)   
            print '  %-30s %-43s' % (optdesc, wrapped_desc[0])
            for line in wrapped_desc[1:]:
                print ' ' * 33 + line
        print
    except KeyError:
        # if the command is an external module, we grab usage help
        # from the module itself.
        if cmd in IMPORTED_COMMANDS:
            try:
                cmd_module =  __import__(cmd, globals(), locals(), 'xen.xm')
                cmd_usage = getattr(cmd_module, "help", None)
                if cmd_usage:
                    print cmd_usage()
            except ImportError:
                pass
        
def shortHelp():
    """Print out generic help when xm is called without subcommand."""
    
    print USAGE_HELP
    print 'Common \'xm\' commands:\n'
    
    for command in common_commands:
        try:
            args, desc = SUBCOMMAND_HELP[command]
        except KeyError:
            continue
        wrapped_desc = wrap(desc, 50)
        print ' %-20s %-50s' % (command, wrapped_desc[0])
        for line in wrapped_desc[1:]:
            print ' ' * 22 + line

    print
    print USAGE_FOOTER
    print 'For a complete list of subcommands run \'xm help\'.'
    
def longHelp():
    """Print out full help when xm is called with xm --help or xm help"""
    
    print USAGE_HELP
    print 'xm full list of subcommands:\n'
    
    for command in all_commands:
        try:
            args, desc = SUBCOMMAND_HELP[command]
        except KeyError:
            continue

        wrapped_desc = wrap(desc, 50)
        print ' %-20s %-50s' % (command, wrapped_desc[0])
        for line in wrapped_desc[1:]:
            print ' ' * 22 + line        

    print
    print USAGE_FOOTER        

def _usage(cmd):
    """ Print help usage information """
    if cmd:
        cmdHelp(cmd)
    else:
        shortHelp()

def usage(cmd = None):
    """ Print help usage information and exits """
    _usage(cmd)
    sys.exit(1)


####################################################################
#
#  Utility functions
#
####################################################################

def get_default_SR():
    return [sr_ref
            for sr_ref in server.xenapi.SR.get_all()
            if server.xenapi.SR.get_type(sr_ref) == "local"][0]

def get_default_Network():
    return [network_ref
            for network_ref in server.xenapi.network.get_all()][0]

class XenAPIUnsupportedException(Exception):
    pass

def xenapi_unsupported():
    if serverType == SERVER_XEN_API:
        raise XenAPIUnsupportedException, "This function is not supported by Xen-API"

def map2sxp(m):
    return [[k, m[k]] for k in m.keys()]

def arg_check(args, name, lo, hi = -1):
    n = len([i for i in args if i != '--'])
    
    if hi == -1:
        if n != lo:
            err("'xm %s' requires %d argument%s.\n" % (name, lo,
                                                       lo == 1 and '' or 's'))
            usage(name)
    else:
        if n < lo or n > hi:
            err("'xm %s' requires between %d and %d arguments.\n" %
                (name, lo, hi))
            usage(name)


def unit(c):
    if not c.isalpha():
        return 0
    base = 1
    if c == 'G' or c == 'g': base = 1024 * 1024 * 1024
    elif c == 'M' or c == 'm': base = 1024 * 1024
    elif c == 'K' or c == 'k': base = 1024
    else:
        print 'ignoring unknown unit'
    return base

def int_unit(str, dest):
    base = unit(str[-1])
    if not base:
        return int(str)

    value = int(str[:-1])
    dst_base = unit(dest)
    if dst_base == 0:
        dst_base = 1
    if dst_base > base:
        return value / (dst_base / base)
    else:
        return value * (base / dst_base)

def err(msg):
    print >>sys.stderr, "Error:", msg


def get_single_vm(dom):
    if serverType == SERVER_XEN_API:
        uuids = server.xenapi.VM.get_by_name_label(dom)
        if len(uuids) > 0:
            return uuids[0]

        try:
            domid = int(dom)
            uuids = [server.xenapi.VM.get_domid(vm_ref)
                     for vm_ref in server.xenapi.VM.get_all()
                     if int(server.xenapi.VM.get_domid(vm_ref)) == domid]
        except:
            pass
            
        if len(uuids) > 0:
            return uuids[0]

        raise OptionError("Domain '%s' not found." % dom)
    else:
        dominfo = server.xend.domain(dom, False)
        return dominfo['uuid']

##
#
# Xen-API Shell
#
##

class Shell(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.prompt = "xm> "
        if serverType == SERVER_XEN_API:
            try:
                res = server.xenapi.host.list_methods()
                for f in res:
                    setattr(Shell, 'do_' + f + ' ', self.default)
            except:
                pass

    def preloop(self):
        cmd.Cmd.preloop(self)
        readline.set_completer_delims(' ')

    def default(self, line):
        words = shlex.split(line)
        if len(words) > 0 and words[0] == 'xm':
            words = words[1:]
        if len(words) > 0:
            cmd = xm_lookup_cmd(words[0])
            if cmd:
                _run_cmd(cmd, words[0], words[1:])
            elif serverType == SERVER_XEN_API:
                ok, res = _run_cmd(lambda x: server.xenapi_request(words[0],
                                                                   tuple(x)),
                                   words[0], words[1:])
                if ok and res is not None and res != '':
                    pprint.pprint(res)
            else:
                print '*** Unknown command: %s' % words[0]
        return False

    def completedefault(self, text, line, begidx, endidx):
        words = shlex.split(line[:begidx])
        clas, func = words[0].split('.')
        if len(words) > 1 or \
           func.startswith('get_by_') or \
           func == 'get_all':
            return []
        uuids = server.xenapi_request('%s.get_all' % clas, ())
        return [u + " " for u in uuids if u.startswith(text)]

    def emptyline(self):
        pass

    def do_EOF(self, line):
        print
        sys.exit(0)

    def do_help(self, line):
        _usage(line)


def xm_shell(args):
    Shell().cmdloop('The Xen Master. Type "help" for a list of functions.')


def xm_event_monitor(args):
    if serverType == SERVER_XEN_API:
        while True:
            server.xenapi.event.register(args)
            events = server.xenapi.event.next()
            for e in events:
                print e
    else:
        err("Event monitoring not supported unless using Xen-API.")


#########################################################################
#
#  Main xm functions
#
#########################################################################

def xm_save(args):

    arg_check(args, "save", 2, 3)
    
    try:
        (options, params) = getopt.gnu_getopt(args, 'c', ['checkpoint'])
    except getopt.GetoptError, opterr:
        err(opterr)
        sys.exit(1)

    dom = params[0]
    savefile = params[1]

    checkpoint = False
    for (k, v) in options:
        if k in ['-c', '--checkpoint']:
            checkpoint = True

    if len(params) != 2:
        err("Wrong number of parameters")
        usage('save')
        sys.exit(1)

    savefile = os.path.abspath(savefile)

    if not os.access(os.path.dirname(savefile), os.W_OK):
        err("xm save: Unable to create file %s" % savefile)
        sys.exit(1)
        
    if serverType == SERVER_XEN_API:       
        server.xenapi.VM.save(get_single_vm(dom), savefile, checkpoint)
    else:
        try:
            dominfo = parse_doms_info(server.xend.domain(dom))
        except xmlrpclib.Fault, ex:
            raise ex
    
        domid = dominfo['domid']
        server.xend.domain.save(domid, savefile, checkpoint)
    
def xm_restore(args):
    arg_check(args, "restore", 1, 2)

    try:
        (options, params) = getopt.gnu_getopt(args, 'p', ['paused'])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('restore')

    paused = False
    for (k, v) in options:
        if k in ['-p', '--paused']:
            paused = True

    if len(params) != 1:
        err("Wrong number of parameters")
        usage('restore')

    savefile = os.path.abspath(params[0])

    if not os.access(savefile, os.R_OK):
        err("xm restore: Unable to read file %s" % savefile)
        sys.exit(1)

    if serverType == SERVER_XEN_API:
        server.xenapi.VM.restore(savefile, paused)
    else:
        server.xend.domain.restore(savefile, paused)


def datetime_to_secs(v):
    unwanted = ":-."
    for c in unwanted:
        v = str(v).replace(c, "")
    return time.mktime(time.strptime(v[0:14], '%Y%m%dT%H%M%S'))

def getDomains(domain_names, state, full = 0):
    if serverType == SERVER_XEN_API:
        doms_sxp = []
        doms_dict = []
        dom_refs = server.xenapi.VM.get_all()
        for dom_ref in dom_refs:
            dom_rec = server.xenapi.VM.get_record(dom_ref)
            dom_metrics_ref = server.xenapi.VM.get_metrics(dom_ref)
            dom_metrics = server.xenapi.VM_metrics.get_record(dom_metrics_ref)

            states = ('running', 'blocked', 'paused', 'shutdown',
                      'crashed', 'dying')
            def state_on_off(state):
                if state in dom_metrics['state']:
                    return state[0]
                else:
                    return "-"
            state_str = "".join([state_on_off(state)
                                 for state in states])
            
            dom_rec.update({'name':     dom_rec['name_label'],
                            'memory_actual': int(dom_metrics['memory_actual'])/1024,
                            'vcpus':    dom_metrics['VCPUs_number'],
                            'state':    state_str,
                            'cpu_time': dom_metrics['VCPUs_utilisation'],
                            'start_time': datetime_to_secs(
                                              dom_metrics['start_time'])})

            doms_sxp.append(['domain'] + map2sxp(dom_rec))
            doms_dict.append(dom_rec)
            
        if domain_names:
            doms = [['domain'] + map2sxp(dom) for dom in doms_dict
                    if dom["name"] in domain_names]
            
            if len(doms) > 0:
                return doms
            else:
                print "Error: no domain%s named %s" % \
                      (len(domain_names) > 1 and 's' or '',
                       ', '.join(domain_names))
                sys.exit(-1)
        else:
            return doms_sxp
    else:
        if domain_names:
            return [server.xend.domain(dom, full) for dom in domain_names]
        else:
            return server.xend.domains_with_state(True, state, full)


def xm_list(args):
    use_long = 0
    show_vcpus = 0
    show_labels = 0
    state = 'all'
    try:
        (options, params) = getopt.gnu_getopt(args, 'lv',
                                              ['long','vcpus','label',
                                               'state='])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('list')
    
    for (k, v) in options:
        if k in ['-l', '--long']:
            use_long = 1
        if k in ['-v', '--vcpus']:
            show_vcpus = 1
        if k in ['--label']:
            show_labels = 1
        if k in ['--state']:
            state = v

    if state != 'all' and len(params) > 0:
        raise OptionError(
            "You may specify either a state or a particular VM, but not both")

    if show_vcpus:
        print >>sys.stderr, (
            "xm list -v is deprecated.  Please use xm vcpu-list.")
        xm_vcpu_list(params)
        return

    doms = getDomains(params, state, use_long)

    if use_long:
        map(PrettyPrint.prettyprint, doms)
    elif show_labels:
        xm_label_list(doms)
    else:
        xm_brief_list(doms)


def parse_doms_info(info):
    def get_info(n, t, d):
        return t(sxp.child_value(info, n, d))

    def get_status(n, t, d):
        return DOM_STATES[t(sxp.child_value(info, n, d))]

    start_time = get_info('start_time', float, -1)
    if start_time == -1:
        up_time = float(-1)
    else:
        up_time = time.time() - start_time

    parsed_info = {
        'domid'    : get_info('domid',              str,   ''),
        'name'     : get_info('name',               str,   '??'),
        'state'    : get_info('state',              str,   ''),

        # VCPUs is the number online when the VM is up, or the number
        # configured otherwise.
        'vcpus'    : get_info('online_vcpus', int,
                              get_info('vcpus', int, 0)),
        'up_time'  : up_time
        }

    # We're not supporting security stuff just yet via XenAPI

    if serverType != SERVER_XEN_API:
        from xen.util import security
        parsed_info['seclabel'] = security.get_security_printlabel(info)
    else:
        parsed_info['seclabel'] = ""

    if serverType == SERVER_XEN_API:
        parsed_info['mem'] = get_info('memory_actual', int, 0) / 1024
        cpu_times = get_info('cpu_time', lambda x : (x), 0.0)
        if sum(cpu_times.values()) > 0:
            parsed_info['cpu_time'] = sum(cpu_times.values()) / float(len(cpu_times.values()))
        else:
            parsed_info['cpu_time'] = 0
    else:
        parsed_info['mem'] = get_info('memory', int,0)
        parsed_info['cpu_time'] = get_info('cpu_time', float, 0.0)

    return parsed_info

def check_sched_type(sched):
    if serverType == SERVER_XEN_API:
        current = server.xenapi.host.get_sched_policy(
            server.xenapi.session.get_this_host(server.getSession()))
    else:
        current = 'unknown'
        for x in server.xend.node.info()[1:]:
            if len(x) > 1 and x[0] == 'xen_scheduler':
                current = x[1]
                break
    if sched != current:
        err("Xen is running with the %s scheduler" % current)
        sys.exit(1)

def parse_sedf_info(info):
    def get_info(n, t, d):
        return t(sxp.child_value(info, n, d))

    return {
        'domid'    : get_info('domid',         int,   -1),
        'period'   : get_info('period',        int,   -1),
        'slice'    : get_info('slice',         int,   -1),
        'latency'  : get_info('latency',       int,   -1),
        'extratime': get_info('extratime',     int,   -1),
        'weight'   : get_info('weight',        int,   -1),
        }

def domid_match(domid, info):
    return domid is None or domid == info['name'] or \
           domid == str(info['domid'])

def xm_brief_list(doms):
    print '%-40s %3s %5s %5s %10s %9s' % \
          ('Name', 'ID', 'Mem', 'VCPUs', 'State', 'Time(s)')
    
    format = "%(name)-40s %(domid)3s %(mem)5d %(vcpus)5d %(state)10s " \
             "%(cpu_time)8.1f"
    
    for dom in doms:
        d = parse_doms_info(dom)
        print format % d

def xm_label_list(doms):
    print '%-32s %3s %5s %5s %5s %9s %-8s' % \
          ('Name', 'ID', 'Mem', 'VCPUs', 'State', 'Time(s)', 'Label')
    
    output = []
    format = '%(name)-32s %(domid)3s %(mem)5d %(vcpus)5d %(state)10s ' \
             '%(cpu_time)8.1f %(seclabel)9s'

    if serverType != SERVER_XEN_API:
        from xen.util import security
        
        for dom in doms:
            d = parse_doms_info(dom)

            if security.active_policy not in ['INACTIVE', 'NULL', 'DEFAULT']:
                if not d['seclabel']:
                    d['seclabel'] = 'ERROR'
            elif security.active_policy in ['DEFAULT']:
                d['seclabel'] = 'DEFAULT'
            else:
                d['seclabel'] = 'INACTIVE'

            output.append((format % d, d['seclabel']))
        
    #sort by labels
    output.sort(lambda x,y: cmp( x[1].lower(), y[1].lower()))
    for line, label in output:
        print line


def xm_vcpu_list(args):
    if serverType == SERVER_XEN_API:
        if args:
            vm_refs = map(get_single_vm, args)
        else:
            vm_refs = server.xenapi.VM.get_all()
            
        vm_records = dict(map(lambda vm_ref:
                                  (vm_ref, server.xenapi.VM.get_record(
                                      vm_ref)),
                              vm_refs))

        vm_metrics = dict(map(lambda (ref, record):
                                  (ref,
                                   server.xenapi.VM_metrics.get_record(
                                       record['metrics'])),
                              vm_records.items()))

        dominfo = []

        # vcpu_list doesn't list 'managed' domains
        # when they are not running, so filter them out

        vm_refs = [vm_ref
                  for vm_ref in vm_refs
                  if vm_records[vm_ref]["power_state"] != "Halted"]

        for vm_ref in vm_refs:
            info = ['domain',
                    ['domid',      vm_records[vm_ref]['domid']],
                    ['name',       vm_records[vm_ref]['name_label']],
                    ['vcpu_count', vm_records[vm_ref]['VCPUs_max']]]

            for i in range(int(vm_records[vm_ref]['VCPUs_max'])):
                def chk_flag(flag):
                    return flag in vm_metrics[vm_ref]['VCPUs_flags'][str(i)] \
                           and 1 or 0
                
                vcpu_info = ['vcpu',
                             ['number',
                                  i],
                             ['online',
                                  chk_flag("online")],
                             ['blocked',
                                  chk_flag("blocked")],
                             ['running',
                                  chk_flag("running")],
                             ['cpu_time',
                                  vm_metrics[vm_ref]['VCPUs_utilisation'][str(i)]],
                             ['cpu',
                                  vm_metrics[vm_ref]['VCPUs_CPU'][str(i)]],
                             ['cpumap',
                                  vm_metrics[vm_ref]['VCPUs_params']\
                                  ['cpumap%i' % i].split(",")]]
                
                info.append(vcpu_info)

            dominfo.append(info)
    else:    
        if args:
            dominfo = map(server.xend.domain.getVCPUInfo, args)
        else:
            doms = server.xend.domains(False)
            dominfo = map(server.xend.domain.getVCPUInfo, doms)

    print '%-32s %3s %5s %5s %5s %9s %s' % \
          ('Name', 'ID', 'VCPU', 'CPU', 'State', 'Time(s)', 'CPU Affinity')

    format = '%(name)-32s %(domid)3d %(number)5d %(c)5s %(s)5s ' \
             ' %(cpu_time)8.1f %(cpumap)s'

    for dom in dominfo:
        def get_info(n):
            return sxp.child_value(dom, n)

        #
        # convert a list of integers into a list of pairs indicating
        # continuous sequences in the list:
        #
        # [0,1,2,3]   -> [(0,3)]
        # [1,2,4,5]   -> [(1,2),(4,5)]
        # [0]         -> [(0,0)]
        # [0,1,4,6,7] -> [(0,1),(4,4),(6,7)]
        #
        def list_to_rangepairs(cmap):
            cmap.sort()
            pairs = []
            x = y = 0
            for i in range(0,len(cmap)):
                try:
                    if ((cmap[y+1] - cmap[i]) > 1):
                        pairs.append((cmap[x],cmap[y]))
                        x = y = i+1
                    else:
                        y = y + 1
                # if we go off the end, then just add x to y
                except IndexError:
                    pairs.append((cmap[x],cmap[y]))

            return pairs

        #
        # Convert pairs to range string, e.g: [(1,2),(3,3),(5,7)] -> 1-2,3,5-7
        #
        def format_pairs(pairs):
            if not pairs:
                return "no cpus"
            out = ""
            for f,s in pairs:
                if (f==s):
                    out += '%d'%f
                else:
                    out += '%d-%d'%(f,s)
                out += ','
            # trim trailing ','
            return out[:-1]

        def format_cpumap(cpumap):
            cpumap = map(lambda x: int(x), cpumap)
            cpumap.sort()

            if serverType == SERVER_XEN_API:
                nr_cpus = len(server.xenapi.host.get_host_CPUs(
                    server.xenapi.session.get_this_host(server.getSession())))
            else:
                for x in server.xend.node.info()[1:]:
                    if len(x) > 1 and x[0] == 'nr_cpus':
                        nr_cpus = int(x[1])

            # normalize cpumap by modulus nr_cpus, and drop duplicates
            cpumap = dict.fromkeys(
                       map(lambda x: x % nr_cpus, cpumap)).keys()
            if len(cpumap) == nr_cpus:
                return "any cpu"

            return format_pairs(list_to_rangepairs(cpumap))

        name  =     get_info('name')
        domid = int(get_info('domid'))

        for vcpu in sxp.children(dom, 'vcpu'):
            def vinfo(n, t):
                return t(sxp.child_value(vcpu, n))

            number   = vinfo('number',   int)
            cpu      = vinfo('cpu',      int)
            cpumap   = format_cpumap(vinfo('cpumap', list))
            online   = vinfo('online',   int)
            cpu_time = vinfo('cpu_time', float)
            running  = vinfo('running',  int)
            blocked  = vinfo('blocked',  int)

            if online:
                c = str(cpu)
                if running:
                    s = 'r'
                else:
                    s = '-'
                if blocked:
                    s += 'b'
                else:
                    s += '-'
                s += '-'
            else:
                c = "-"
                s = "--p"

            print format % locals()

def xm_start(args):
    arg_check(args, "start", 1, 2)

    try:
        (options, params) = getopt.gnu_getopt(args, 'p', ['paused'])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('start')

    paused = False
    for (k, v) in options:
        if k in ['-p', '--paused']:
            paused = True

    if len(params) != 1:
        err("Wrong number of parameters")
        usage('start')

    dom = params[0]
    if serverType == SERVER_XEN_API:
        server.xenapi.VM.start(get_single_vm(dom), paused)
    else:
        server.xend.domain.start(dom, paused)

def xm_delete(args):
    arg_check(args, "delete", 1)
    dom = args[0]
    if serverType == SERVER_XEN_API:
        server.xenapi.VM.destroy(get_single_vm(dom))
    else:
        server.xend.domain.delete(dom)

def xm_suspend(args):
    arg_check(args, "suspend", 1)
    dom = args[0]
    if serverType == SERVER_XEN_API:
        server.xenapi.VM.suspend(get_single_vm(dom))
    else:
        server.xend.domain.suspend(dom)

def xm_resume(args):
    arg_check(args, "resume", 1, 2)

    try:
        (options, params) = getopt.gnu_getopt(args, 'p', ['paused'])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('resume')

    paused = False
    for (k, v) in options:
        if k in ['-p', '--paused']:
            paused = True

    if len(params) != 1:
        err("Wrong number of parameters")
        usage('resume')

    dom = params[0]
    if serverType == SERVER_XEN_API:
        server.xenapi.VM.resume(get_single_vm(dom), paused)
    else:
        server.xend.domain.resume(dom, paused)
    
def xm_reboot(args):
    arg_check(args, "reboot", 1, 3)
    from xen.xm import shutdown
    shutdown.main(["shutdown", "-R"] + args)

def xm_shutdown(args):
    arg_check(args, "shutdown", 1, 4)
    from xen.xm import shutdown
    shutdown.main(["shutdown"] + args)

def xm_pause(args):
    arg_check(args, "pause", 1)
    dom = args[0]

    if serverType == SERVER_XEN_API:
        server.xenapi.VM.pause(get_single_vm(dom))
    else:
        server.xend.domain.pause(dom)

def xm_unpause(args):
    arg_check(args, "unpause", 1)
    dom = args[0]

    if serverType == SERVER_XEN_API:
        server.xenapi.VM.unpause(get_single_vm(dom))
    else:
        server.xend.domain.unpause(dom)

def xm_dump_core(args):
    live = False
    crash = False
    try:
        (options, params) = getopt.gnu_getopt(args, 'LC', ['live','crash'])
        for (k, v) in options:
            if k in ('-L', '--live'):
                live = True
            if k in ('-C', '--crash'):
                crash = True

        if len(params) not in (1, 2):
            raise OptionError("Expects 1 or 2 argument(s)")
    except getopt.GetoptError, e:
        raise OptionError(str(e))
    
    dom = params[0]
    if len(params) == 2:
        filename = os.path.abspath(params[1])
    else:
        filename = None

    if not live:
        server.xend.domain.pause(dom)

    try:
        print "Dumping core of domain: %s ..." % str(dom)
        server.xend.domain.dump(dom, filename, live, crash)
    finally:
        if not live:
            server.xend.domain.unpause(dom)

    if crash:
        print "Destroying domain: %s ..." % str(dom)
        server.xend.domain.destroy(dom)

def xm_rename(args):
    arg_check(args, "rename", 2)
        
    if serverType == SERVER_XEN_API:
        server.xenapi.VM.set_name_label(get_single_vm(args[0]), args[1])
    else:
        server.xend.domain.setName(args[0], args[1])

def xm_importcommand(command, args):
    cmd = __import__(command, globals(), locals(), 'xen.xm')
    cmd.main([command] + args)


#############################################################

def xm_vcpu_pin(args):
    arg_check(args, "vcpu-pin", 3)

    def cpu_make_map(cpulist):
        cpus = []
        for c in cpulist.split(','):
            if c.find('-') != -1:
                (x,y) = c.split('-')
                for i in range(int(x),int(y)+1):
                    cpus.append(int(i))
            else:
                # remove this element from the list
                if c[0] == '^':
                    cpus = [x for x in cpus if x != int(c[1:])]
                else:
                    cpus.append(int(c))
        cpus.sort()
        return cpus

    dom  = args[0]
    vcpu = int(args[1])
    if args[2] == 'all':
        cpumap = cpu_make_map('0-63')
    else:
        cpumap = cpu_make_map(args[2])

    if serverType == SERVER_XEN_API:
        cpumap = map(str, cpumap)        
        server.xenapi.VM.add_to_VCPUs_params_live(
            get_single_vm(dom), "cpumap%i" % int(vcpu), ",".join(cpumap))
    else:
        server.xend.domain.pincpu(dom, vcpu, cpumap)

def xm_mem_max(args):
    arg_check(args, "mem-max", 2)

    dom = args[0]

    if serverType == SERVER_XEN_API:
        mem = int_unit(args[1], 'k') * 1024
        server.xenapi.VM.set_memory_static_max(get_single_vm(dom), mem)
    else:
        mem = int_unit(args[1], 'm')
        server.xend.domain.maxmem_set(dom, mem)
    
def xm_mem_set(args):
    arg_check(args, "mem-set", 2)

    dom = args[0]

    if serverType == SERVER_XEN_API:
        mem_target = int_unit(args[1], 'm') * 1024 * 1024
        server.xenapi.VM.set_memory_dynamic_max_live(get_single_vm(dom),
                                                     mem_target)
        server.xenapi.VM.set_memory_dynamic_min_live(get_single_vm(dom),
                                                     mem_target)
    else:
        mem_target = int_unit(args[1], 'm')
        server.xend.domain.setMemoryTarget(dom, mem_target)
    
def xm_vcpu_set(args):
    arg_check(args, "vcpu-set", 2)

    dom = args[0]
    vcpus = int(args[1])

    if serverType == SERVER_XEN_API:
        server.xenapi.VM.set_VCPUs_number_live(get_single_vm(dom), vcpus)
    else:
        server.xend.domain.setVCpuCount(dom, vcpus)

def xm_destroy(args):
    arg_check(args, "destroy", 1)

    dom = args[0]
    
    if serverType == SERVER_XEN_API:
        server.xenapi.VM.hard_shutdown(get_single_vm(dom))
    else:
        server.xend.domain.destroy(dom)

def xm_domid(args):
    arg_check(args, "domid", 1)

    name = args[0]

    if serverType == SERVER_XEN_API:
        print server.xenapi.VM.get_domid(get_single_vm(name))
    else:
        dom = server.xend.domain(name)
        print sxp.child_value(dom, 'domid')
    
def xm_domname(args):
    arg_check(args, "domname", 1)

    name = args[0]
    
    if serverType == SERVER_XEN_API:
        print server.xenapi.VM.get_name_label(get_single_vm(name))
    else:
        dom = server.xend.domain(name)
        print sxp.child_value(dom, 'name')

def xm_sched_sedf(args):
    xenapi_unsupported()
    
    def ns_to_ms(val):
        return float(val) * 0.000001
    
    def ms_to_ns(val):
        return (float(val) / 0.000001)

    def print_sedf(info):
        info['period']  = ns_to_ms(info['period'])
        info['slice']   = ns_to_ms(info['slice'])
        info['latency'] = ns_to_ms(info['latency'])
        print( ("%(name)-32s %(domid)3d %(period)9.1f %(slice)9.1f" +
                " %(latency)7.1f %(extratime)6d %(weight)6d") % info)

    check_sched_type('sedf')

    # we want to just display current info if no parameters are passed
    if len(args) == 0:
        domid = None
    else:
        # we expect at least a domain id (name or number)
        # and at most a domid up to 5 options with values
        arg_check(args, "sched-sedf", 1, 11)
        domid = args[0]
        # drop domid from args since get_opt doesn't recognize it
        args = args[1:] 

    opts = {}
    try:
        (options, params) = getopt.gnu_getopt(args, 'p:s:l:e:w:',
            ['period=', 'slice=', 'latency=', 'extratime=', 'weight='])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('sched-sedf')
    
    # convert to nanoseconds if needed 
    for (k, v) in options:
        if k in ['-p', '--period']:
            opts['period'] = ms_to_ns(v)
        elif k in ['-s', '--slice']:
            opts['slice'] = ms_to_ns(v)
        elif k in ['-l', '--latency']:
            opts['latency'] = ms_to_ns(v)
        elif k in ['-e', '--extratime']:
            opts['extratime'] = v
        elif k in ['-w', '--weight']:
            opts['weight'] = v

    doms = filter(lambda x : domid_match(domid, x),
                        [parse_doms_info(dom)
                         for dom in getDomains(None, 'running')])
    if domid is not None and doms == []: 
        err("Domain '%s' does not exist." % domid)
        usage('sched-sedf')

    # print header if we aren't setting any parameters
    if len(opts.keys()) == 0:
        print '%-33s %-2s %-4s %-4s %-7s %-5s %-6s' % \
              ('Name','ID','Period(ms)', 'Slice(ms)', 'Lat(ms)',
               'Extra','Weight')
    
    for d in doms:
        # fetch current values so as not to clobber them
        try:
            sedf_raw = server.xend.domain.cpu_sedf_get(d['domid'])
        except xmlrpclib.Fault:
            # domain does not support sched-sedf?
            sedf_raw = {}

        sedf_info = parse_sedf_info(sedf_raw)
        sedf_info['name'] = d['name']
        # update values in case of call to set
        if len(opts.keys()) > 0:
            for k in opts.keys():
                sedf_info[k]=opts[k]
         
            # send the update, converting user input
            v = map(int, [sedf_info['period'], sedf_info['slice'],
                          sedf_info['latency'],sedf_info['extratime'], 
                          sedf_info['weight']])
            rv = server.xend.domain.cpu_sedf_set(d['domid'], *v)
            if int(rv) != 0:
                err("Failed to set sedf parameters (rv=%d)."%(rv))

        # not setting values, display info
        else:
            print_sedf(sedf_info)

def xm_sched_credit(args):
    """Get/Set options for Credit Scheduler."""
    
    check_sched_type('credit')

    try:
        opts, params = getopt.getopt(args, "d:w:c:",
            ["domain=", "weight=", "cap="])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('sched-credit')

    domid = None
    weight = None
    cap = None

    for o, a in opts:
        if o == "-d":
            domid = a
        elif o == "-w":
            weight = int(a)
        elif o == "-c":
            cap = int(a);

    doms = filter(lambda x : domid_match(domid, x),
                  [parse_doms_info(dom)
                  for dom in getDomains(None, 'running')])

    if weight is None and cap is None:
        if domid is not None and doms == []: 
            err("Domain '%s' does not exist." % domid)
            usage('sched-credit')
        # print header if we aren't setting any parameters
        print '%-33s %-2s %-6s %-4s' % ('Name','ID','Weight','Cap')
        
        for d in doms:
            try:
                if serverType == SERVER_XEN_API:
                    info = server.xenapi.VM_metrics.get_VCPUs_params(
                        server.xenapi.VM.get_metrics(
                            get_single_vm(d['name'])))
                else:
                    info = server.xend.domain.sched_credit_get(d['domid'])
            except xmlrpclib.Fault:
                pass

            if 'weight' not in info or 'cap' not in info:
                # domain does not support sched-credit?
                info = {'weight': -1, 'cap': -1}

            info['weight'] = int(info['weight'])
            info['cap']    = int(info['cap'])
            
            info['name']  = d['name']
            info['domid'] = int(d['domid'])
            print( ("%(name)-32s %(domid)3d %(weight)6d %(cap)4d") % info)
    else:
        if domid is None:
            # place holder for system-wide scheduler parameters
            err("No domain given.")
            usage('sched-credit')

        if serverType == SERVER_XEN_API:
            server.xenapi.VM.add_to_VCPUs_params_live(
                get_single_vm(domid),
                "weight",
                weight)
            server.xenapi.VM.add_to_VCPUs_params_live(
                get_single_vm(domid),
                "cap",
                cap)            
        else:
            result = server.xend.domain.sched_credit_set(domid, weight, cap)
            if result != 0:
                err(str(result))

def xm_info(args):
    arg_check(args, "info", 0)

    if serverType == SERVER_XEN_API:

        # Need to fake out old style xm info as people rely on parsing it
        
        host_record = server.xenapi.host.get_record(
            server.xenapi.session.get_this_host(server.getSession()))

        host_cpu_records = map(server.xenapi.host_cpu.get_record, host_record["host_CPUs"])

        host_metrics_record = server.xenapi.host_metrics.get_record(host_record["metrics"])

        info = {
            "host":              host_record["name_label"],
            "release":           host_record["software_version"]["release"],
            "version":           host_record["software_version"]["version"],
            "machine":           host_record["software_version"]["machine"],
            "nr_cpus":           len(host_record["host_CPUs"]),
            "nr_nodes":          host_record["cpu_configuration"]["nr_nodes"],
            "sockets_per_node":  host_record["cpu_configuration"]["sockets_per_node"],
            "cores_per_socket":  host_record["cpu_configuration"]["cores_per_socket"],
            "threads_per_core":  host_record["cpu_configuration"]["threads_per_core"],
            "cpu_mhz":           sum([int(host_cpu_record["speed"]) for host_cpu_record in host_cpu_records])
                                   / len(host_cpu_records),
            "hw_caps":           host_cpu_records[0]["features"],
            "total_memory":      int(host_metrics_record["memory_total"])/1024/1024,
            "free_memory":       int(host_metrics_record["memory_free"])/1024/1024,
            "xen_major":         host_record["software_version"]["xen_major"],
            "xen_minor":         host_record["software_version"]["xen_minor"],
            "xen_extra":         host_record["software_version"]["xen_extra"],
            "xen_caps":          " ".join(host_record["capabilities"]),
            "xen_scheduler":     host_record["sched_policy"],
            "xen_pagesize":      host_record["other_config"]["xen_pagesize"],
            "platform_params":   host_record["other_config"]["platform_params"],
            "xen_changeset":     host_record["software_version"]["xen_changeset"],
            "cc_compiler":       host_record["software_version"]["cc_compiler"],
            "cc_compile_by":     host_record["software_version"]["cc_compile_by"],
            "cc_compile_domain": host_record["software_version"]["cc_compile_domain"],
            "cc_compile_date":   host_record["software_version"]["cc_compile_date"],
            "xend_config_format":host_record["software_version"]["xend_config_format"]                                
        }

        sorted = info.items()
        sorted.sort(lambda (x1,y1), (x2,y2): -cmp(x1,x2))
        
        for (k, v) in sorted:
           print "%-23s:" % k, v 
    else:
        info = server.xend.node.info()
        for x in info[1:]:
            if len(x) < 2: 
                print "%-23s: (none)" % x[0]
            else: 
                print "%-23s:" % x[0], x[1]

def xm_console(args):
    arg_check(args, "console", 1, 2)

    quiet = False;

    try:
        (options, params) = getopt.gnu_getopt(args, 'q', ['quiet'])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('console')

    for (k, v) in options:
        if k in ['-q', '--quiet']:
            quiet = True
        else:
            assert False

    if len(params) != 1:
        err('No domain given')
        usage('console')

    dom = params[0]

    try:
        if serverType == SERVER_XEN_API:
            domid = int(server.xenapi.VM.get_domid(get_single_vm(dom)))
        else:
            info = server.xend.domain(dom)
            domid = int(sxp.child_value(info, 'domid', '-1'))
    except:
        if quiet:
            sys.exit(1)
        else:
            raise
        
    if domid == -1:
        if quiet:
            sys.exit(1)
        else:
            raise xmlrpclib.Fault(0, "Domain '%s' is not started" % dom)

    console.execConsole(domid)


def xm_uptime(args):
    short_mode = 0

    try:
        (options, params) = getopt.gnu_getopt(args, 's', ['short'])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('uptime')

    for (k, v) in options:
        if k in ['-s', '--short']:
            short_mode = 1

    doms = getDomains(params, 'running')

    if short_mode == 0:
        print 'Name                              ID Uptime'

    for dom in doms:
        d = parse_doms_info(dom)
        if int(d['domid']) > 0:
            uptime = int(round(d['up_time']))
        else:
            f=open('/proc/uptime', 'r')
            upfile = f.read()
            uptime = int(round(float(upfile.split(' ')[0])))
            f.close()

        days = int(uptime / 86400)
        uptime -= (days * 86400)
        hours = int(uptime / 3600)
        uptime -= (hours * 3600)
        minutes = int(uptime / 60)
        uptime -= (minutes * 60)
        seconds = uptime
            
        upstring = ""
        if days > 0:
            upstring += str(days) + " day"
            if days > 1:
                upstring += "s"
            upstring += ", "
        upstring += '%(hours)2d:%(minutes)02d' % vars()

        if short_mode:
            now = datetime.datetime.now()
            upstring = now.strftime(" %H:%M:%S") + " up " + upstring
            upstring += ", " + d['name'] + " (" + d['domid'] + ")"
        else:
            upstring += ':%(seconds)02d' % vars()
            upstring = ("%(name)-32s %(domid)3s " % d) + upstring

        print upstring

def xm_sysrq(args):
    arg_check(args, "sysrq", 2)
    dom = args[0]
    req = args[1]
    if serverType == SERVER_XEN_API:
        server.xenapi.VM.send_sysrq(get_single_vm(dom), req)
    else:
        server.xend.domain.send_sysrq(dom, req)

def xm_trigger(args):
    vcpu = 0
    
    arg_check(args, "trigger", 2, 3)
    dom = args[0]
    trigger = args[1]
    if len(args) == 3:
        vcpu = int(args[2])
        
    if serverType == SERVER_XEN_API:
        server.xenapi.VM.send_trigger(get_single_vm(dom), trigger, vcpu)
    else:
        server.xend.domain.send_trigger(dom, trigger, vcpu)

def xm_debug_keys(args):
    arg_check(args, "debug-keys", 1)

    keys = str(args[0])
    
    if serverType == SERVER_XEN_API:
        server.xenapi.host.send_debug_keys(
            server.xenapi.session.get_this_host(server.getSession()),
            keys)
    else:
        server.xend.node.send_debug_keys(keys)

def xm_top(args):
    arg_check(args, "top", 0)

    os.execvp('xentop', ['xentop'])

def xm_dmesg(args):
    arg_check(args, "dmesg", 0, 1)
    
    try:
        (options, params) = getopt.gnu_getopt(args, 'c', ['clear'])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('dmesg')
    
    use_clear = 0
    for (k, v) in options:
        if k in ['-c', '--clear']:
            use_clear = 1
    
    if len(params) :
        err("No parameter required")
        usage('dmesg')

    if serverType == SERVER_XEN_API:
        host = server.xenapi.session.get_this_host(server.getSession())
        if use_clear:
            print server.xenapi.host.dmesg_clear(host),
        else:
            print server.xenapi.host.dmesg(host),
    else:
        if not use_clear:
            print server.xend.node.dmesg.info(),
        else:
            print server.xend.node.dmesg.clear(),

def xm_log(args):
    arg_check(args, "log", 0)

    if serverType == SERVER_XEN_API:
        print server.xenapi.host.get_log(
            server.xenapi.session.get_this_host(server.getSession()))
    else:
        print server.xend.node.log()

def xm_serve(args):
    if serverType == SERVER_XEN_API:
        print "Not supported with XenAPI"
        sys.exit(-1)

    arg_check(args, "serve", 0)

    from fcntl import fcntl, F_SETFL
    
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(XendClient.XML_RPC_SOCKET)
    fcntl(sys.stdin, F_SETFL, os.O_NONBLOCK)

    while True:
        iwtd, owtd, ewtd = select([sys.stdin, s], [], [])
        if s in iwtd:
            data = s.recv(4096)
            if len(data) > 0:
                sys.stdout.write(data)
                sys.stdout.flush()
            else:
                break
        if sys.stdin in iwtd:
            data = sys.stdin.read(4096)
            if len(data) > 0:
                s.sendall(data)
            else:
                break
    s.close()

def parse_dev_info(info):
    def get_info(n, t, d):
        i = 0
        while i < len(info):
            if (info[i][0] == n):
                return t(info[i][1])
            i = i + 1
        return t(d)
    return {
        #common
        'backend-id' : get_info('backend-id',   int,   -1),
        'handle'     : get_info('handle',       int,    0),
        'state'      : get_info('state',        int,   -1),
        'be-path'    : get_info('backend',      str,   '??'),
        'event-ch'   : get_info('event-channel',int,   -1),
        #network specific
        'virtual-device' : get_info('virtual-device', str, '??'),
        'tx-ring-ref': get_info('tx-ring-ref',  int,   -1),
        'rx-ring-ref': get_info('rx-ring-ref',  int,   -1),
        'mac'        : get_info('mac',          str,   '??'),
        #block-device specific
        'ring-ref'   : get_info('ring-ref',     int,   -1),
        }

def arg_check_for_resource_list(args, name):
    use_long = 0
    try:
        (options, params) = getopt.gnu_getopt(args, 'l', ['long'])
    except getopt.GetoptError, opterr:
        err(opterr)
        sys.exit(1)

    for (k, v) in options:
        if k in ['-l', '--long']:
            use_long = 1

    if len(params) == 0:
        print 'No domain parameter given'
        usage(name)
    if len(params) > 1:
        print 'No multiple domain parameters allowed'
        usage(name)
    
    return (use_long, params)

def xm_network_list(args):
    (use_long, params) = arg_check_for_resource_list(args, "network-list")

    dom = params[0]

    if serverType == SERVER_XEN_API:
        vif_refs = server.xenapi.VM.get_VIFs(get_single_vm(dom))
        vif_properties = \
            map(server.xenapi.VIF.get_runtime_properties, vif_refs)
        devs = map(lambda (handle, properties): [handle, map2sxp(properties)],
                   zip(range(len(vif_properties)), vif_properties))
    else:
        devs = server.xend.domain.getDeviceSxprs(dom, 'vif')
        
    if use_long:
        map(PrettyPrint.prettyprint, devs)
    else:
        hdr = 0
        for x in devs:
            if hdr == 0:
                print 'Idx BE     MAC Addr.     handle state evt-ch tx-/rx-ring-ref BE-path'
                hdr = 1
            ni = parse_dev_info(x[1])
            ni['idx'] = int(x[0])
            print ("%(idx)-3d "
                   "%(backend-id)-3d"
                   "%(mac)-17s    "
                   "%(handle)-3d   "
                   "%(state)-3d    "
                   "%(event-ch)-3d   "
                   "%(tx-ring-ref)-5d/%(rx-ring-ref)-5d   "
                   "%(be-path)-30s  "
                   % ni)

def xm_block_list(args):
    (use_long, params) = arg_check_for_resource_list(args, "block-list")

    dom = params[0]

    if serverType == SERVER_XEN_API:
        vbd_refs = server.xenapi.VM.get_VBDs(get_single_vm(dom))
        vbd_properties = \
            map(server.xenapi.VBD.get_runtime_properties, vbd_refs)
        vbd_devs = \
            map(server.xenapi.VBD.get_device, vbd_refs)
        vbd_devids = \
            map(blkdev_name_to_number, vbd_devs)
        devs = map(lambda (devid, prop): [devid, map2sxp(prop)],
                   zip(vbd_devids, vbd_properties))
    else:
        devs = server.xend.domain.getDeviceSxprs(dom, 'vbd')

    if use_long:
        map(PrettyPrint.prettyprint, devs)
    else:
        hdr = 0
        for x in devs:
            if hdr == 0:
                print 'Vdev  BE handle state evt-ch ring-ref BE-path'
                hdr = 1
            ni = parse_dev_info(x[1])
            ni['idx'] = int(x[0])
            print ("%(idx)-3d    "
                   "%(backend-id)-3d  "
                   "%(handle)-3d   "
                   "%(state)-3d    "
                   "%(event-ch)-3d    "
                   "%(ring-ref)-5d "
                   "%(be-path)-30s  "
                   % ni)

def xm_vtpm_list(args):
    xenapi_unsupported()
    (use_long, params) = arg_check_for_resource_list(args, "vtpm-list")

    dom = params[0]
    if use_long:
        devs = server.xend.domain.getDeviceSxprs(dom, 'vtpm')
        map(PrettyPrint.prettyprint, devs)
    else:
        hdr = 0
        for x in server.xend.domain.getDeviceSxprs(dom, 'vtpm'):
            if hdr == 0:
                print 'Idx  BE handle state evt-ch ring-ref BE-path'
                hdr = 1
            ni = parse_dev_info(x[1])
            ni['idx'] = int(x[0])
            print ("%(idx)-3d   "
                   "%(backend-id)-3d  "
                   "%(handle)-3d   "
                   "%(state)-3d    "
                   "%(event-ch)-3d    "
                   "%(ring-ref)-5d "
                   "%(be-path)-30s  "
                   % ni)


def parse_block_configuration(args):
    dom = args[0]

    if args[1].startswith('tap:'):
        cls = 'tap'
    else:
        cls = 'vbd'

    vbd = [cls,
           ['uname', args[1]],
           ['dev',   args[2]],
           ['mode',  args[3]]]
    if len(args) == 5:
        vbd.append(['backend', args[4]])

    if serverType != SERVER_XEN_API:
        # verify that policy permits attaching this resource
        from xen.util import security
    
        if security.on():
            dominfo = server.xend.domain(dom)
            label = security.get_security_printlabel(dominfo)
        else:
            label = None

        security.res_security_check(args[1], label)

    return (dom, vbd)


def xm_block_attach(args):
    arg_check(args, 'block-attach', 4, 5)

    if serverType == SERVER_XEN_API:
        dom   = args[0]
        uname = args[1]
        dev   = args[2]
        mode  = args[3]

        # First create new VDI
        vdi_record = {
            "name_label":       "vdi" + str(uname.__hash__()),   
            "name_description": "",
            "SR":               get_default_SR(),
            "virtual_size":     0,
            "sector_size":      512,
            "type":             "system",
            "sharable":         False,
            "read_only":        mode!="w",
            "other_config":     {"location": uname}
        }

        vdi_ref = server.xenapi.VDI.create(vdi_record)

        # Now create new VBD

        vbd_record = {
            "VM":               get_single_vm(dom),
            "VDI":              vdi_ref,
            "device":           dev,
            "bootable":         True,
            "mode":             mode=="w" and "RW" or "RO",
            "type":             "Disk",
            "qos_algorithm_type": "",
            "qos_algorithm_params": {}
        }

        server.xenapi.VBD.create(vbd_record)
        
    else:
        (dom, vbd) = parse_block_configuration(args)
        server.xend.domain.device_create(dom, vbd)


def xm_block_configure(args):
    arg_check(args, 'block-configure', 4, 5)

    (dom, vbd) = parse_block_configuration(args)
    server.xend.domain.device_configure(dom, vbd)


def xm_network_attach(args):
    arg_check(args, 'network-attach', 1, 10)

    dom = args[0]
    vif = ['vif']
    vif_params = ['type', 'mac', 'bridge', 'ip', 'script', \
                  'backend', 'vifname', 'rate', 'model']

    if serverType == SERVER_XEN_API:     
        vif_record = {
            "device":               "eth0",
            "network":              get_default_Network(),
            "VM":                   get_single_vm(dom),
            "MAC":                  "",
            "MTU":                  "",
            "qos_algorithm_type":   "",
            "qos_algorithm_params": {},
            "other_config":         {}
            }

        def set(keys, val):
            record = vif_record
            for key in keys[:-1]:
                record = record[key]
            record[keys[-1]] = val

        def get_net_from_bridge(bridge):
            raise "Not supported just yet"
         
        vif_conv = {
            'type':
                lambda x: None,
            'mac':
                lambda x: set(['MAC'], x),
            'bridge':
                lambda x: set(['network'], get_net_from_bridge(x)),
            'ip':
                lambda x: set(['other_config', 'ip'], x),
            'script':
                lambda x: set(['other_config', 'script'], x),
            'backend':
                lambda x: set(['other_config', 'backend'], x),
            'vifname':
                lambda x: set(['device'], x),
            'rate':
                lambda x: set(['qos_algorithm_params', 'rate'], x),
            'model':
                lambda x: None
            }
            
        for a in args[1:]:
            vif_param = a.split("=")
            if len(vif_param) != 2 or vif_param[1] == '' or \
                   vif_param[0] not in vif_params:
                err("Invalid argument: %s" % a)
                usage('network-attach')   
            else:
                vif_conv[vif_param[0]](vif_param[1])

        print str(vif_record)
        server.xenapi.VIF.create(vif_record)
    else:
        for a in args[1:]:
            vif_param = a.split("=")
            if len(vif_param) != 2 or vif_param[1] == '' or \
                   vif_param[0] not in vif_params:
                err("Invalid argument: %s" % a)
                usage('network-attach')
            vif.append(vif_param)
        server.xend.domain.device_create(dom, vif)


def detach(args, command, deviceClass):
    arg_check(args, command, 2, 3)

    dom = args[0]
    dev = args[1]
    try:
        force = args[2]
        if (force != "--force") and (force != "-f"):
            print "Ignoring option %s"%(force)
            force = None
    except IndexError:
        force = None

    server.xend.domain.destroyDevice(dom, deviceClass, dev, force)


def xm_block_detach(args):
    if serverType == SERVER_XEN_API:
        arg_check(args, "xm_block_detach", 2, 3)
        dom = args[0]
        dev = args[1]
        vbd_refs = server.xenapi.VM.get_VBDs(get_single_vm(dom))
        vbd_refs = [vbd_ref for vbd_ref in vbd_refs
                    if server.xenapi.VBD.get_device(vbd_ref) == dev]
        if len(vbd_refs) > 0:
            vbd_ref = vbd_refs[0]
            vdi_ref = server.xenapi.VBD.get_VDI(vbd_ref)

            server.xenapi.VBD.destroy(vbd_ref)

            if len(server.xenapi.VDI.get_VBDs(vdi_ref)) <= 0:
                server.xenapi.VDI.destroy(vdi_ref)
        else:
            raise OptionError("Cannot find device '%s' in domain '%s'"
                              % (dev,dom))
    else:
        try:
            detach(args, 'block-detach', 'vbd')
            return
        except:
            pass
        detach(args, 'block-detach', 'tap')

def xm_network_detach(args):
    if serverType == SERVER_XEN_API:
        arg_check(args, "xm_block_detach", 2, 3)
        dom = args[0]
        devid = args[1]
        vif_refs = server.xenapi.VM.get_VIFs(get_single_vm(dom))
        vif_refs = [vif_ref for vif_ref in vif_refs
                    if server.xenapi.VIF.\
                    get_runtime_properties(vif_ref)["handle"] == devid]
        if len(vif_refs) > 0:
            vif_ref = vif_refs[0]
            
            server.xenapi.VIF.destroy(vif_ref)
        else:
            print "Cannot find device '%s' in domain '%s'" % (devid,dom)
    else:
        detach(args, 'network-detach', 'vif')


def xm_vnet_list(args):
    xenapi_unsupported()
    try:
        (options, params) = getopt.gnu_getopt(args, 'l', ['long'])
    except getopt.GetoptError, opterr:
        err(opterr)
        usage('vnet-list')
    
    use_long = 0
    for (k, v) in options:
        if k in ['-l', '--long']:
            use_long = 1
            
    if params:
        use_long = 1
        vnets = params
    else:
        vnets = server.xend_vnets()
    
    for vnet in vnets:
        try:
            if use_long:
                info = server.xend_vnet(vnet)
                PrettyPrint.prettyprint(info)
            else:
                print vnet
        except Exception, ex:
            print vnet, ex

def xm_vnet_create(args):
    xenapi_unsupported()
    arg_check(args, "vnet-create", 1)
    conf = args[0]
    if not os.access(conf, os.R_OK):
        print "File not found: %s" % conf
        sys.exit(1)

    server.xend_vnet_create(conf)

def xm_vnet_delete(args):
    xenapi_unsupported()
    arg_check(args, "vnet-delete", 1)
    vnet = args[0]
    server.xend_vnet_delete(vnet)

commands = {
    "shell": xm_shell,
    "event-monitor": xm_event_monitor,
    # console commands
    "console": xm_console,
    # xenstat commands
    "top": xm_top,
    # domain commands
    "delete": xm_delete,
    "destroy": xm_destroy,
    "domid": xm_domid,
    "domname": xm_domname,
    "dump-core": xm_dump_core,
    "reboot": xm_reboot,
    "rename": xm_rename,
    "restore": xm_restore,
    "resume": xm_resume,
    "save": xm_save,
    "shutdown": xm_shutdown,
    "start": xm_start,
    "sysrq": xm_sysrq,
    "trigger": xm_trigger,
    "uptime": xm_uptime,
    "suspend": xm_suspend,
    "list": xm_list,
    # memory commands
    "mem-max": xm_mem_max,
    "mem-set": xm_mem_set,
    # cpu commands
    "vcpu-pin": xm_vcpu_pin,
    "vcpu-list": xm_vcpu_list,
    "vcpu-set": xm_vcpu_set,
    # special
    "pause": xm_pause,
    "unpause": xm_unpause,
    # host commands
    "debug-keys": xm_debug_keys,
    "dmesg": xm_dmesg,
    "info": xm_info,
    "log": xm_log,
    "serve": xm_serve,
    # scheduler
    "sched-sedf": xm_sched_sedf,
    "sched-credit": xm_sched_credit,
    # block
    "block-attach": xm_block_attach,
    "block-detach": xm_block_detach,
    "block-list": xm_block_list,
    "block-configure": xm_block_configure,
    # network
    "network-attach": xm_network_attach,
    "network-detach": xm_network_detach,
    "network-list": xm_network_list,
    # vnet
    "vnet-list": xm_vnet_list,
    "vnet-create": xm_vnet_create,
    "vnet-delete": xm_vnet_delete,
    # vtpm
    "vtpm-list": xm_vtpm_list,
    }

## The commands supported by a separate argument parser in xend.xm.
IMPORTED_COMMANDS = [
    'create',
    'new',    
    'migrate',
    'labels',
    'cfgbootpolicy',
    'makepolicy',
    'loadpolicy',
    'dumppolicy',        
    'addlabel',
    'rmlabel',
    'getlabel',
    'dry-run',
    'resources',
    ]

for c in IMPORTED_COMMANDS:
    commands[c] = eval('lambda args: xm_importcommand("%s", args)' % c)

aliases = {
    "balloon": "mem-set",
    "set-vcpus": "vcpu-set",
    "vif-list": "network-list",
    "vbd-create": "block-attach",
    "vbd-destroy": "block-detach",
    "vbd-list": "block-list",
    }


def xm_lookup_cmd(cmd):
    if commands.has_key(cmd):
        return commands[cmd]
    elif aliases.has_key(cmd):
        deprecated(cmd,aliases[cmd])
        return commands[aliases[cmd]]
    elif cmd == 'help':
        longHelp()
        sys.exit(0)
    else:
        # simulate getopt's prefix matching behaviour
        if len(cmd) > 1:
            same_prefix_cmds = [commands[c] for c in commands.keys() \
                                if c[:len(cmd)] == cmd]
            # only execute if there is only 1 match
            if len(same_prefix_cmds) == 1:
                return same_prefix_cmds[0]
        return None

def deprecated(old,new):
    print >>sys.stderr, (
        "Command %s is deprecated.  Please use xm %s instead." % (old, new))

def main(argv=sys.argv):
    if len(argv) < 2:
        usage()

    # intercept --help(-h) and output our own help
    for help in ['--help', '-h']:
        if help in argv[1:]:
            if help == argv[1]:
                longHelp()
                sys.exit(0)
            else:
                usage(argv[1])

    cmd_name = argv[1]
    cmd = xm_lookup_cmd(cmd_name)
    if cmd:
        # strip off prog name and subcmd
        args = argv[2:]
        _, rc = _run_cmd(cmd, cmd_name, args)
        sys.exit(rc)
    else:
        err('Subcommand %s not found!' % cmd_name)
        usage()

def _run_cmd(cmd, cmd_name, args):
    global server

    try:
        if server is None:
            if serverType == SERVER_XEN_API:
                server = XenAPI.Session(serverURI)
                username, password = parseAuthentication()
                server.login_with_password(username, password)
                def logout():
                    try:
                        server.xenapi.session.logout()
                    except:
                        pass
                atexit.register(logout)
            else:
                server = ServerProxy(serverURI)

        return True, cmd(args)
    except socket.error, ex:
        if os.geteuid() != 0:
            err("Most commands need root access. Please try again as root.")
        else:
            err("Unable to connect to xend: %s. Is xend running?" % ex[1])
    except KeyboardInterrupt:
        print "Interrupted."
        return True, ''
    except IOError, ex:
        if os.geteuid() != 0:
            err("Most commands need root access.  Please try again as root.")
        else:
            err("Unable to connect to xend: %s." % ex[1])
    except SystemExit, code:
        return code == 0, code
    except XenAPI.Failure, exn:
        for line in [''] + wrap(str(exn), 80) + ['']:
            print >>sys.stderr, line
    except xmlrpclib.Fault, ex:
        if ex.faultCode == XendClient.ERROR_INVALID_DOMAIN:
            err("Domain '%s' does not exist." % ex.faultString)
        else:
            err(ex.faultString)
            _usage(cmd_name)
    except xmlrpclib.ProtocolError, ex:
        if ex.errcode == -1:
            print  >>sys.stderr, (
                "Xend has probably crashed!  Invalid or missing HTTP "
                "status code.")
        else:
            print  >>sys.stderr, (
                "Xend has probably crashed!  ProtocolError(%d, %s)." %
                (ex.errcode, ex.errmsg))
    except (ValueError, OverflowError):
        err("Invalid argument.")
        _usage(cmd_name)
    except OptionError, e:
        err(str(e))
        _usage(cmd_name)
        print e.usage
    except XenAPIUnsupportedException, e:
        err(str(e))
    except Exception, e:
        if serverType != SERVER_XEN_API:
           from xen.util import security
           if isinstance(e, security.ACMError):
               err(str(e))
               return False, 1
        print "Unexpected error:", sys.exc_info()[0]
        print
        print "Please report to xen-devel@lists.xensource.com"
        raise

    return False, 1

if __name__ == "__main__":
    main()
