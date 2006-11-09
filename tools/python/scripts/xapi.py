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
from getpass import getpass

MB = 1024 * 1024

HOST_INFO_FORMAT = '%-20s: %-50s'
VM_LIST_FORMAT = '%(name_label)-18s %(memory_actual)-5s %(vcpus_number)-5s'\
                 ' %(power_state)-10s %(uuid)-36s'
SR_LIST_FORMAT = '%(name_label)-18s %(uuid)-36s %(physical_size)-10s' \
                 '%(type)-10s'
VDI_LIST_FORMAT = '%(name_label)-18s %(uuid)-36s %(virtual_size)-8s '\
                  '%(sector_size)-8s'

COMMANDS = {
    'host-info': ('', 'Get Xen Host Info'),
    'sr-list':   ('', 'List all SRs'),
    'vbd-create': ('<domname> <pycfg> [opts]',
                   'Create VBD attached to domname'),
    'vdi-create': ('<pycfg> [opts]', 'Create a VDI'),
    'vdi-list'  : ('', 'List all VDI'),
    'vdi-rename': ('<vdi_uuid> <new_name>', 'Rename VDI'),
    'vdi-delete': ('<vdi_uuid>', 'Delete VDI'),
    'vif-create': ('<domname> <pycfg>', 'Create VIF attached to domname'),
    'vtpm-create' : ('<domname> <pycfg>', 'Create VTPM attached to domname'),

    'vm-create': ('<pycfg>', 'Create VM with python config'),
    'vm-destroy': ('<domname>', 'Delete VM'),
    
    'vm-list':   ('[--long]', 'List all domains.'),
    'vm-name':   ('<uuid>', 'Name of UUID.'),
    'vm-shutdown': ('<name> [opts]', 'Shutdown VM with name'),
    'vm-start':  ('<name>', 'Start VM with name'),
    'vm-uuid':   ('<name>', 'UUID of a domain by name.'),    
}

OPTIONS = {
    'vm-list': [(('-l', '--long'),
                 {'action':'store_true',
                  'help':'List all properties of VMs'})
               ],
    'vm-shutdown': [(('-f', '--force'), {'help': 'Shutdown Forcefully',
                                         'action': 'store_true'})],
    
    'vdi-create': [(('--name-label',), {'help': 'Name for VDI'}),
                   (('--description',), {'help': 'Description for VDI'}),
                   (('--sector-size',), {'type': 'int',
                                         'help': 'Sector size'}),
                   (('--virtual-size',), {'type': 'int',
                                          'help': 'Size of VDI in sectors'}),
                   (('--type',), {'choices': ['system', 'user', 'ephemeral'],
                                  'help': 'VDI type'}),
                   (('--sharable',), {'action': 'store_true',
                                      'help': 'VDI sharable'}),
                   (('--read-only',), {'action': 'store_true',
                                       'help': 'Read only'})],
    
    'vbd-create': [(('--VDI',), {'help': 'UUID of VDI to attach to.'}),
                   (('--mode',), {'choices': ['RO', 'RW'],
                                  'help': 'device mount mode'}),
                   (('--driver',), {'choices':['paravirtualised', 'ioemu'],
                                    'help': 'Driver for VBD'}),
                   (('--device',), {'help': 'Device name on guest domain'}),
                   (('--image',), {'help': 'Location of drive image.'})]
                   
}

class OptionError(Exception):
    pass

class XenAPIError(Exception):
    pass

# 
# Extra utility functions
#

class IterableValues(Values):
    """Better interface to the list of values from optparse."""

    def __iter__(self):
        for opt, val in self.__dict__.items():
            if opt[0] == '_' or callable(val):
                continue
            yield opt, val        


def parse_args(cmd_name, args, set_defaults = False):
    argstring, desc = COMMANDS[cmd_name]
    parser = OptionParser(usage = 'xapi %s %s' % (cmd_name, argstring),
                          description = desc)
    if cmd_name in OPTIONS:
        for optargs, optkwds in OPTIONS[cmd_name]:
            parser.add_option(*optargs, **optkwds)

    if set_defaults:
        default_values = parser.get_default_values()
        defaults = IterableValues(default_values.__dict__)
    else:
        defaults = IterableValues()
    (opts, extraargs) = parser.parse_args(args = list(args),
                                          values = defaults)
    return opts, extraargs

def execute(fn, *args):
    result = fn(*args)
    if type(result) != DictType:
        raise TypeError("Function returned object of type: %s" %
                        str(type(result)))
    if 'Value' not in result:
        raise XenAPIError(*result['ErrorDescription'])
    return result['Value']

_initialised = False
_server = None
_session = None
def _connect(*args):
    global _server, _session, _initialised
    if not _initialised:
        _server = ServerProxy('httpu:///var/run/xend/xmlrpc.sock')
        login = raw_input("Login: ")
        password = getpass()
        creds = (login, password)
        _session = execute(_server.session.login_with_password, *creds)
        _initialised = True
    return (_server, _session)

def _stringify(adict):
    return dict([(k, str(v)) for k, v in adict.items()])

def _read_python_cfg(filename):
    cfg = {}
    execfile(filename, {}, cfg)
    return cfg

def resolve_vm(server, session, vm_name):
    vm_uuid = execute(server.VM.get_by_name_label, session, vm_name)
    if not vm_uuid:
        return None
    else:
        return vm_uuid[0]

#
# Actual commands
#

def xapi_host_info(*args):
    server, session = _connect()
    hosts = execute(server.host.get_all, session)
    for host in hosts: # there is only one, but ..
        hostinfo = execute(server.host.get_record, session, host)
        print HOST_INFO_FORMAT % ('Name', hostinfo['name_label'])
        print HOST_INFO_FORMAT % ('Version', hostinfo['software_version'])
        print HOST_INFO_FORMAT % ('CPUs', len(hostinfo['host_CPUs']))
        print HOST_INFO_FORMAT % ('VMs', len(hostinfo['resident_VMs']))
        print HOST_INFO_FORMAT % ('UUID', host)        

def xapi_vm_uuid(*args):
    if len(args) < 1:
        raise OptionError("No domain name specified")
    
    server, session = _connect()
    vm_uuid = resolve_vm(server, session, args[0])
    print vm_uuid

def xapi_vm_name(*args):
    if len(args) < 1:
        raise OptionError("No UUID specified")
    
    server, session = _connect()
    vm_name = execute(server.VM.get_name_label, session, args[0])
    print vm_name

def xapi_vm_list(*args):
    opts, args = parse_args('vm-list', args, set_defaults = True)
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
            vtpms = vm_info['vtpms']
            vif_infos = []
            vbd_infos = []
            vtpm_infos = []
            for vbd in vbds:
                vbd_info = execute(server.VBD.get_record, session, vbd)
                vbd_infos.append(vbd_info)
            for vif in vifs:
                vif_info = execute(server.VIF.get_record, session, vif)
                vif_infos.append(vif_info)
            for vtpm in vtpms:
                vtpm_info = execute(server.VTPM.get_record, session, vtpm)
                vtpm_infos.append(vtpm_info)
            vm_info['vbds'] = vbd_infos
            vm_info['vifs'] = vif_infos
            vm_info['vtpms'] = vtpm_infos
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

def xapi_vm_destroy(*args):
    if len(args) < 1:
        raise OptionError("No domain name specified.")
    
    server, session = _connect()
    vm_uuid = resolve_vm(server, session, args[0])    
    print 'Destroying VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server.VM.destroy, session, vm_uuid)
    print 'Done.'
    

def xapi_vm_start(*args):
    if len(args) < 1:
        raise OptionError("No Domain name specified.")
    
    server, session = _connect()
    vm_uuid = resolve_vm(server, session, args[0])
    print 'Starting VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server.VM.start, session, vm_uuid)
    print 'Done.'

def xapi_vm_shutdown(*args):
    opts, args = parse_args("vm-shutdown", args, set_defaults = True)
    
    if len(args) < 1:
        raise OptionError("No Domain name specified.")

    server, session = _connect()
    vm_uuid = resolve_vm(server, session, args[0])
    if opts.force:
        print 'Forcefully shutting down VM %s (%s)' % (args[0], vm_uuid)
        success = execute(server.VM.hard_shutdown, session, vm_uuid)
    else:
        print 'Shutting down VM %s (%s)' % (args[0], vm_uuid)
        success = execute(server.VM.clean_shutdown, session, vm_uuid)
    print 'Done.'

def xapi_vbd_create(*args):
    opts, args = parse_args('vbd-create', args)

    if len(args) < 2:
        raise OptionError("Configuration file and domain not specified")

    domname = args[0]

    if len(args) > 1:
        filename = args[1]
        cfg = _read_python_cfg(filename)
    else:
        cfg = {}
        
    for opt, val in opts:
        cfg[opt] = val
    
    print 'Creating VBD ...',
    server, session = _connect()
    vm_uuid = resolve_vm(server, session, domname)
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
    vm_uuid = resolve_vm(server, session, domname)
    cfg['VM'] = vm_uuid
    vif_uuid = execute(server.VIF.create, session, cfg)
    print 'Done. (%s)' % vif_uuid

def xapi_vdi_list(*args):
    server, session = _connect()
    vdis = execute(server.VDI.get_all, session)

    print VDI_LIST_FORMAT % {'name_label': 'VDI Label',
                             'uuid' : 'UUID',
                             'virtual_size': 'Sectors',
                             'sector_size': 'Sector Size'}
    
    for vdi in vdis:
        vdi_struct = execute(server.VDI.get_record, session, vdi)
        print VDI_LIST_FORMAT % vdi_struct

def xapi_sr_list(*args):
    server, session = _connect()
    srs = execute(server.SR.get_all, session)
    print SR_LIST_FORMAT % {'name_label': 'SR Label',
                            'uuid' : 'UUID',
                            'physical_size': 'Size',
                            'type': 'Type'}
    for sr in srs:
        sr_struct = execute(server.SR.get_record, session, sr)
        sr_struct['physical_size'] = int(sr_struct['physical_size'])/MB
        print SR_LIST_FORMAT % sr_struct

def xapi_vdi_create(*args):
    opts, args = parse_args('vdi-create', args)

    if len(args) > 0:
        cfg = _read_python_cfg(args[0])
    else:
        cfg = {}
        
    for opt, val in opts:
        cfg[opt] = val

    server, session = _connect()
    srs = execute(server.SR.get_all, session)
    sr = srs[0]
    cfg['SR'] = sr

    size = (cfg['virtual_size'] * cfg['sector_size'])/MB
    print 'Creating VDI of size: %dMB ..' % size,
    uuid = execute(server.VDI.create, session, cfg)
    print 'Done. (%s)' % uuid

def xapi_vdi_delete(*args):
    server, session = _connect()
    if len(args) < 1:
        raise OptionError('Not enough arguments')

    vdi_uuid = args[0]
    print 'Deleting VDI %s' % vdi_uuid
    result = execute(server.VDI.destroy, session, vdi_uuid)
    print 'Done.'

def xapi_vdi_rename(*args):
    server, session = _connect()
    if len(args) < 2:
        raise OptionError('Not enough arguments')

    vdi_uuid = args[0]
    vdi_name = args[1]
    print 'Renaming VDI %s to %s' % (vdi_uuid, vdi_name)
    result = execute(server.VDI.set_name_label, session, vdi_uuid, vdi_name)
    print 'Done.'


def xapi_vtpm_create(*args):
    server, session = _connect()
    domname = args[0]
    cfg = _read_python_cfg(args[1])

    vm_uuid = resolve_vm(server, session, domname)
    cfg['VM'] = vm_uuid
    print "Creating vTPM with cfg = %s" % cfg
    vtpm_uuid = execute(server.VTPM.create, session, cfg)
    print "Done. (%s)" % vtpm_uuid
    vtpm_id = execute(server.VTPM.get_instance, session, vtpm_uuid)
    print "Has instance number '%s'" % vtpm_id
    vtpm_be = execute(server.VTPM.get_backend, session, vtpm_uuid)
    print "Has backend in '%s'" % vtpm_be
    driver = execute(server.VTPM.get_driver, session, vtpm_uuid)
    print "Has driver type '%s'" % driver
    vtpm_rec = execute(server.VTPM.get_record, session, vtpm_uuid)
    print "Has vtpm record '%s'" % vtpm_rec
    vm = execute(server.VTPM.get_VM, session, vtpm_uuid)
    print "Has VM '%s'" % vm


#
# Command Line Utils
#
import cmd
import shlex

class XenAPICmd(cmd.Cmd):
    def __init__(self, server, session):
        cmd.Cmd.__init__(self)
        self.server = server
        self.session = session
        self.prompt = ">>> "

    def default(self, line):
        words = shlex.split(line)
        if len(words) > 0:
            cmd_name = words[0].replace('-', '_')
            func_name = 'xapi_%s' % cmd_name
            func = globals().get(func_name)
            if func:
                try:
                    args = tuple(words[1:])
                    func(*args)
                    return True
                except SystemExit:
                    return False
                except OptionError, e:
                    print 'Error:', str(e)
                    return False
                except Exception, e:
                    import traceback
                    traceback.print_exc()
                    return False
        print '*** Unknown command: %s' % words[0]
        return False

    def do_EOF(self, line):
        print
        sys.exit(0)

    def do_help(self, line):
        usage(print_usage = False)

    def emptyline(self):
        pass

    def postcmd(self, stop, line):
        return False

    def precmd(self, line):
        words = shlex.split(line)
        if len(words) > 0:
            words0 = words[0].replace('-', '_')
            return ' '.join([words0] + words[1:])
        else:
            return line

def shell():
    server, session = _connect()
    x = XenAPICmd(server, session)
    x.cmdloop('Xen API Prompt. Type "help" for a list of functions')

def usage(command = None, print_usage = True):
    if not command:
        if print_usage:
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

    if subcmd == 'shell':
        shell()
    elif not subcmd_func or not callable(subcmd_func):
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
    except OptionError, e:
        print 'Error: %s' % e

    sys.exit(0)
    
if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
