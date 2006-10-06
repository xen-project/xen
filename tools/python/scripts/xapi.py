#!/usr/bin/python
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
# Copyright (C) 2006 XenSource Ltd.
#============================================================================

from xen.util.xmlrpclib2 import ServerProxy
from optparse import *
from pprint import pprint
from types import DictType

HOST_INFO_FORMAT = '%-20s: %-50s'
VM_LIST_FORMAT = '%(name_label)-24s %(memory_actual)-5s %(vcpus_number)-5s'\
                 ' %(power_state)-5s %(uuid)-32s'

LOGIN = ('atse', 'passwd')

COMMANDS = {
    'host-info': ('', 'Get Xen Host Info'),
    'vbd-create': ('<domname> <pycfg>', 'Create VBD attached to domname'),
    'vif-create': ('<domname> <pycfg>', 'Create VIF attached to domname'),

    'vm-create': ('<pycfg>', 'Create VM with python config'),
    'vm-delete': ('<domname>', 'Delete VM'),
    
    'vm-destroy': ('<name>', 'Hard shutdown a VM with name'),
    'vm-list':   ('[--long]', 'List all domains.'),
    'vm-name':   ('<uuid>', 'Name of UUID.'),
    'vm-shutdown': ('<name>', 'Shutdown VM with name'),
    'vm-start':  ('<name>', 'Start VM with name'),
    'vm-uuid':   ('<name>', 'UUID of a domain by name.'),    
}

OPTIONS = {
    'vm-list': [(('-l', '--long'),
                 {'action':'store_true',
                  'help':'List all properties of VMs'})
               ],
   
}

class OptionError(Exception):
    pass

class XenAPIError(Exception):
    pass

# 
# Extra utility functions
#

def parse_args(cmd_name, args):
    argstring, desc = COMMANDS[cmd_name]
    parser = OptionParser(usage = 'xapi %s %s' % (cmd_name, argstring),
                          description = desc)
    if cmd_name in OPTIONS:
        for optargs, optkwds in OPTIONS[cmd_name]:
            parser.add_option(*optargs, **optkwds)
            
    (opts, extraargs) = parser.parse_args(list(args))
    return opts, extraargs

def execute(fn, *args):
    result = fn(*args)
    if type(result) != DictType:
        raise TypeError("Function returned object of type: %s" %
                        str(type(result)))
    if 'Value' not in result:
        raise XenAPIError(*result['ErrorDescription'])
    return result['Value']


def _connect(*args):
    server = ServerProxy('httpu:///var/run/xend/xmlrpc.sock')        
    session = execute(server.Session.login_with_password, *LOGIN)
    host = execute(server.Session.get_this_host, session)
    return (server, session)

def _stringify(adict):
    return dict([(k, str(v)) for k, v in adict.items()])

def _read_python_cfg(filename):
    cfg = {}
    execfile(filename, {}, cfg)
    return cfg

#
# Actual commands
#

def xapi_host_info(*args):
    server, session = _connect()
    hosts = execute(server.Host.get_all, session)
    for host in hosts: # there is only one, but ..
        hostinfo = execute(server.Host.get_record, session, host)
        print HOST_INFO_FORMAT % ('Name', hostinfo['name_label'])
        print HOST_INFO_FORMAT % ('Version', hostinfo['software_version'])
        print HOST_INFO_FORMAT % ('CPUs', len(hostinfo['host_CPUs']))
        print HOST_INFO_FORMAT % ('VMs', len(hostinfo['resident_VMs']))
        print HOST_INFO_FORMAT % ('UUID', host)        

def xapi_vm_uuid(*args):
    if len(args) < 1:
        raise OptionError("No domain name specified")
    
    server, session = _connect()
    vm_uuid = execute(server.VM.get_by_label, session, args[0])
    print vm_uuid

def xapi_vm_name(*args):
    if len(args) < 1:
        raise OptionError("No UUID specified")
    
    server, session = _connect()
    vm_name = execute(server.VM.get_name_label, session, args[0])
    print vm_name

def xapi_vm_list(*args):
    opts, args = parse_args('vm-list', args)
    is_long = opts and opts.long
    
    server, session = _connect()
    vm_uuids = execute(server.VM.get_all, session)
    if not is_long:
        print VM_LIST_FORMAT % {'name_label':'Name',
                                'memory_actual':'Mem',
                                'vcpus_number': 'VCPUs',
                                'power_state': 'State',
                                'uuid': 'UUID'}

    for uuid in vm_uuids:
        vm_info = execute(server.VM.get_record, session, uuid)
        if is_long:
            vbds = vm_info['vbds']
            vifs = vm_info['vifs']
            vif_infos = []
            vbd_infos = []
            for vbd in vbds:
                vbd_info = execute(server.VBD.get_record, session, vbd)
                vbd_infos.append(vbd_info)
            for vif in vifs:
                vif_info = execute(server.VIF.get_record, session, vif)
                vif_infos.append(vif_info)
            vm_info['vbds'] = vbd_infos
            vm_info['vifs'] = vif_infos
            pprint(vm_info)
        else:
            print VM_LIST_FORMAT % _stringify(vm_info)

def xapi_vm_create(*args):
    if len(args) < 1:
        raise OptionError("Configuration file not specified")

    filename = args[0]
    cfg = _read_python_cfg(filename)

    print 'Creating VM from %s ..' % filename
    server, session = _connect()
    uuid = execute(server.VM.create, session, cfg)
    print 'Done. (%s)' % uuid
    print uuid

def xapi_vm_delete(*args):
    if len(args) < 1:
        raise OptionError("No domain name specified.")
    
    server, session = _connect()
    vm_uuid = execute(server.VM.get_by_label, session, args[0])
    print 'Destroying VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server.VM.destroy, session, vm_uuid)
    print 'Done.'
    

def xapi_vm_start(*args):
    if len(args) < 1:
        raise OptionError("No Domain name specified.")
    
    server, session = _connect()
    vm_uuid = execute(server.VM.get_by_label, session, args[0])
    print 'Starting VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server.VM.start, session, vm_uuid)
    print 'Done.'

def xapi_vm_shutdown(*args):
    if len(args) < 1:
        raise OptionError("No Domain name specified.")

    server, session = _connect()
    vm_uuid = execute(server.VM.get_by_label, session, args[0])
    print 'Shutting down VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server.VM.clean_shutdown, session, vm_uuid)
    print 'Done.'

def xapi_vm_destroy(*args):
    if len(args) < 1:
        raise OptionError("No Domain name specified.")

    server, session = _connect()
    vm_uuid = execute(server.VM.get_by_label, session, args[0])
    print 'Shutting down VM with force %s (%s)' % (args[0], vm_uuid)
    success = execute(server.VM.hard_shutdown, session, vm_uuid)
    print 'Done.'    

def xapi_vbd_create(*args):
    if len(args) < 2:
        raise OptionError("Configuration file not specified")

    domname = args[0]
    filename = args[1]
    cfg = _read_python_cfg(filename)
    print 'Creating VBD from %s ..' % filename
    server, session = _connect()
    vm_uuid = execute(server.VM.get_by_label, session, domname)
    cfg['VM'] = vm_uuid
    vbd_uuid = execute(server.VBD.create, session, cfg)
    print 'Done. (%s)' % vbd_uuid

def xapi_vif_create(*args):
    if len(args) < 2:
        raise OptionError("Configuration file not specified")

    domname = args[0]
    filename = args[1]
    cfg = _read_python_cfg(filename)
    print 'Creating VIF from %s ..' % filename
    server, session = _connect()
    vm_uuid = execute(server.VM.get_by_label, session, domname)
    cfg['VM'] = vm_uuid
    vif_uuid = execute(server.VIF.create, session, cfg)
    print 'Done. (%s)' % vif_uuid

    

#
# Command Line Utils
#

def usage(command = None):
    if not command:
        print 'Usage: xapi <subcommand> [options] [args]'
        print
        print 'Subcommands:'
        print
        sorted_commands = sorted(COMMANDS.keys())
        for command  in sorted_commands:
            args, description = COMMANDS[command]
            print '%-16s  %-40s' % (command, description)
        print
    else:
        parse_args(command, ['-h'])

def main(args):

    if len(args) < 1 or args[0] in ('-h', '--help', 'help'):
        usage()
        sys.exit(1)

    subcmd = args[0]

    subcmd_func_name = 'xapi_' + subcmd.replace('-', '_')
    subcmd_func = globals().get(subcmd_func_name, None)
    if not subcmd_func or not callable(subcmd_func):
        print 'Error: Unable to find subcommand \'%s\'' % subcmd
        usage()
        sys.exit(1)

    if '-h' in args[1:] or '--help' in args[1:]:
        usage(subcmd)
        sys.exit(1)
        
    try:
        subcmd_func(*args[1:])
    except XenAPIError, e:
        print 'Error: %s' % str(e.args[1])
        sys.exit(2)

    sys.exit(0)
    
if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
