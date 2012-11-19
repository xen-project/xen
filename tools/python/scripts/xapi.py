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

import sys
import time
import re
import os

from xen.util.xmlrpclib2 import ServerProxy
from optparse import *
from pprint import pprint
from types import DictType
from getpass import getpass

# Get default values from the environment
SERVER_URI = os.environ.get('XAPI_SERVER_URI', 'http://localhost:9363/')
SERVER_USER = os.environ.get('XAPI_SERVER_USER', '')
SERVER_PASS = os.environ.get('XAPI_SERVER_PASS', '')

MB = 1024 * 1024

HOST_INFO_FORMAT = '%-20s: %-50s'
VM_LIST_FORMAT = '%(name_label)-18s %(memory_actual)-5s %(VCPUs_number)-5s'\
                 ' %(power_state)-10s %(uuid)-36s'
SR_LIST_FORMAT = '%(name_label)-18s %(uuid)-36s %(physical_size)-10s' \
                 '%(type)-10s'
VDI_LIST_FORMAT = '%(name_label)-18s %(uuid)-36s %(virtual_size)-8s'
VBD_LIST_FORMAT = '%(device)-6s %(uuid)-36s %(VDI)-8s'
TASK_LIST_FORMAT = '%(name_label)-18s %(uuid)-36s %(status)-8s %(progress)-4s'
VIF_LIST_FORMAT = '%(name)-8s %(device)-7s %(uuid)-36s %(MAC)-10s'
CONSOLE_LIST_FORMAT = '%(uuid)-36s %(protocol)-8s %(location)-32s'

COMMANDS = {
    'host-info': ('', 'Get Xen Host Info'),
    'host-set-name': ('', 'Set host name'),
    'pif-list': ('', 'List all PIFs'),
    'sr-list':   ('', 'List all SRs'),
    'vbd-list':  ('', 'List all VBDs'),
    'vbd-create': ('<domname> <pycfg> [opts]',
                   'Create VBD attached to domname'),
    'vdi-create': ('<pycfg> [opts]', 'Create a VDI'),
    'vdi-list'  : ('', 'List all VDI'),
    'vdi-rename': ('<vdi_uuid> <new_name>', 'Rename VDI'),
    'vdi-destroy': ('<vdi_uuid>', 'Delete VDI'),
    'vif-create': ('<domname> <pycfg>', 'Create VIF attached to domname'),

    'vm-create': ('<pycfg>', 'Create VM with python config'),
    'vm-destroy': ('<domname>', 'Delete VM'),
    
    'vm-list':   ('[--long]', 'List all domains.'),
    'vm-name':   ('<uuid>', 'Name of UUID.'),
    'vm-shutdown': ('<name> [opts]', 'Shutdown VM with name'),
    'vm-start':  ('<name>', 'Start VM with name'),
    'vm-uuid':   ('<name>', 'UUID of a domain by name.'),
    'async-vm-start': ('<name>', 'Start VM asynchronously'),
}

OPTIONS = {
    'sr-list': [(('-l', '--long'),
                 {'action':'store_true',
                  'help':'List all properties of SR'})
               ],

    'vdi-list': [(('-l', '--long'),
                  {'action':'store_true',
                   'help':'List all properties of VDI'})
                 ],
    'vif-list': [(('-l', '--long'),
                  {'action':'store_true',
                   'help':'List all properties of VIF'})
                 ],            
    'vm-list': [(('-l', '--long'),
                 {'action':'store_true',
                  'help':'List all properties of VMs'})
               ],
    'vm-shutdown': [(('-f', '--force'), {'help': 'Shutdown Forcefully',
                                         'action': 'store_true'})],
    
    'vdi-create': [(('--name-label',), {'help': 'Name for VDI'}),
                   (('--name-description',), {'help': 'Description for VDI'}),
                   (('--virtual-size',), {'type': 'int',
                                          'default': 0,
                                          'help': 'Size of VDI in bytes'}),
                   (('--type',), {'choices': ['system', 'user', 'ephemeral'],
                                  'default': 'system',
                                  'help': 'VDI type'}),
                   (('--sharable',), {'action': 'store_true',
                                      'help': 'VDI sharable'}),
                   (('--read-only',), {'action': 'store_true',
                                       'help': 'Read only'}),
                   (('--sr',), {})],
    
    'vbd-create': [(('--VDI',), {'help': 'UUID of VDI to attach to.'}),
                   (('--mode',), {'choices': ['RO', 'RW'],
                                  'help': 'device mount mode'}),
                   (('--driver',), {'choices':['paravirtualised', 'ioemu'],
                                    'help': 'Driver for VBD'}),
                   (('--device',), {'help': 'Device name on guest domain'})]
                   
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

def execute(server, fn, args, async = False):
    if async:
        func = eval('server.Async.%s' % fn)
    else:
        func = eval('server.%s' % fn)
        
    result = func(*args)
    if type(result) != DictType:
        raise TypeError("Function returned object of type: %s" %
                        str(type(result)))
    if 'Value' not in result:
        raise XenAPIError(*result['ErrorDescription'])
    return result['Value']

_initialised = False
_server = None
_session = None
def connect(*args):
    global _server, _session, _initialised
    
    if not _initialised:
        # try without password or default credentials
        try:
            _server = ServerProxy(SERVER_URI)
            _session = execute(_server.session, 'login_with_password',
                               (SERVER_USER, SERVER_PASS))
        except:
            login = raw_input("Login: ")
            password = getpass()
            creds = (login, password)            
            _server = ServerProxy(SERVER_URI)
            _session = execute(_server.session, 'login_with_password',
                               creds)

        _initialised = True
    return (_server, _session)

def _stringify(adict):
    return dict([(k, str(v)) for k, v in adict.items()])

def _read_python_cfg(filename):
    cfg = {}
    execfile(filename, {}, cfg)
    return cfg

def resolve_vm(server, session, vm_name):
    vm_uuid = execute(server, 'VM.get_by_name_label', (session, vm_name))
    if not vm_uuid:
        return None
    else:
        return vm_uuid[0]

def resolve_vdi(server, session, vdi_name):
    vdi_uuid = execute(server, 'VDI.get_by_name_label', (session, vdi_name))
    if not vdi_uuid:
        return None
    else:
        return vdi_uuid[0]

#
# Actual commands
#

def xapi_host_info(args, async = False):
    server, session = connect()
    hosts = execute(server, 'host.get_all', (session,))
    for host in hosts: # there is only one, but ..
        hostinfo = execute(server, 'host.get_record', (session, host))
        print HOST_INFO_FORMAT % ('Name', hostinfo['name_label'])
        print HOST_INFO_FORMAT % ('Version', hostinfo['software_version'])
        print HOST_INFO_FORMAT % ('CPUs', len(hostinfo['host_CPUs']))
        print HOST_INFO_FORMAT % ('VMs', len(hostinfo['resident_VMs']))
        print HOST_INFO_FORMAT % ('UUID', host)        

        for host_cpu_uuid in hostinfo['host_CPUs']:
            host_cpu = execute(server, 'host_cpu.get_record',
                               (session, host_cpu_uuid))
            print 'CPU %s Util: %.2f' % (host_cpu['number'],
                                         float(host_cpu['utilisation']))
        
def xapi_host_set_name(args, async = False):
    if len(args) < 1:
        raise OptionError("No hostname specified")
    
    server, session = connect()
    hosts = execute(server, 'host.get_all', (session,))
    if len(hosts) > 0:
        execute(server, 'host.set_name_label', (session, hosts[0], args[0]))
        print 'Hostname: %s' % execute(server, 'host.get_name_label',
                                       (session, hosts[0]))

def xapi_vm_uuid(args, async = False):
    if len(args) < 1:
        raise OptionError("No domain name specified")
    
    server, session = connect()
    vm_uuid = resolve_vm(server, session, args[0])
    print vm_uuid

def xapi_vm_name(args, async = False):
    if len(args) < 1:
        raise OptionError("No UUID specified")
    
    server, session = connect()
    vm_name = execute(server, 'VM.get_name_label', (session, args[0]))
    print vm_name

def xapi_vm_list(args, async = False):
    opts, args = parse_args('vm-list', args, set_defaults = True)
    is_long = opts and opts.long

    list_only = args
    
    server, session = connect()
    vm_uuids = execute(server, 'VM.get_all', (session,))
    if not is_long:
        print VM_LIST_FORMAT % {'name_label':'Name',
                                'memory_actual':'Mem',
                                'VCPUs_number': 'VCPUs',
                                'power_state': 'State',
                                'uuid': 'UUID'}

    for uuid in vm_uuids:
        vm_info = execute(server, 'VM.get_record', (session, uuid))

        # skip domain if we don't want
        if list_only and vm_info['name_label'] not in list_only:
            continue
        
        if is_long:
            vbds = vm_info['VBDs']
            vifs = vm_info['VIFs']
            vif_infos = []
            vbd_infos = []
            for vbd in vbds:
                vbd_info = execute(server, 'VBD.get_record', (session, vbd))
                vbd_infos.append(vbd_info)
            for vif in vifs:
                vif_info = execute(server, 'VIF.get_record', (session, vif))
                vif_infos.append(vif_info)
            vm_info['VBDs'] = vbd_infos
            vm_info['VIFs'] = vif_infos
            pprint(vm_info)
        else:
            print VM_LIST_FORMAT % _stringify(vm_info)

def xapi_vm_create(args, async = False):
    if len(args) < 1:
        raise OptionError("Configuration file not specified")

    filename = args[0]
    cfg = _read_python_cfg(filename)

    print 'Creating VM from %s ..' % filename
    server, session = connect()
    uuid = execute(server, 'VM.create', (session, cfg), async = async)
    print 'Done. (%s)' % uuid
    print uuid

def xapi_vm_destroy(args, async = False):
    if len(args) < 1:
        raise OptionError("No domain name specified.")
    
    server, session = connect()
    vm_uuid = resolve_vm(server, session, args[0])    
    print 'Destroying VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server, 'VM.destroy', (session, vm_uuid), async = async)
    print 'Done.'
    

def xapi_vm_start(args, async = False):
    if len(args) < 1:
        raise OptionError("No Domain name specified.")
    
    server, session = connect()
    vm_uuid = resolve_vm(server, session, args[0])
    print 'Starting VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server, 'VM.start', (session, vm_uuid, False), async = async)
    if async:
        print 'Task started: %s' % success
    else:
        print 'Done.'

def xapi_vm_suspend(args, async = False):
    if len(args) < 1:
        raise OptionError("No Domain name specified.")
    
    server, session = connect()
    vm_uuid = resolve_vm(server, session, args[0])
    print 'Suspending VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server, 'VM.suspend', (session, vm_uuid), async = async)
    if async:
        print 'Task started: %s' % success
    else:
        print 'Done.'        


def xapi_vm_resume(args, async = False):
    if len(args) < 1:
        raise OptionError("No Domain name specified.")
    
    server, session = connect()
    vm_uuid = resolve_vm(server, session, args[0])
    print 'Resuming VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server, 'VM.resume', (session, vm_uuid, False), async = async)
    if async:
        print 'Task started: %s' % success
    else:
        print 'Done.'

def xapi_vm_pause(args, async = False):
    if len(args) < 1:
        raise OptionError("No Domain name specified.")
    
    server, session = connect()
    vm_uuid = resolve_vm(server, session, args[0])
    print 'Pausing VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server, 'VM.pause', (session, vm_uuid), async = async)
    if async:
        print 'Task started: %s' % success
    else:
        print 'Done.'

def xapi_vm_unpause(args, async = False):
    if len(args) < 1:
        raise OptionError("No Domain name specified.")
    
    server, session = connect()
    vm_uuid = resolve_vm(server, session, args[0])
    print 'Pausing VM %s (%s)' % (args[0], vm_uuid)
    success = execute(server, 'VM.unpause', (session, vm_uuid), async = async)
    if async:
        print 'Task started: %s' % success
    else:
        print 'Done.'                        

def xapi_task_list(args, async = False):
    server, session = connect()
    all_tasks = execute(server, 'task.get_all', (session,))

    print TASK_LIST_FORMAT % {'name_label': 'Task Name',
                              'uuid': 'UUID',
                              'status': 'Status',
                              'progress': '%'}
    
    for task_uuid in all_tasks:
        task = execute(server, 'task.get_record', (session, task_uuid))
        print TASK_LIST_FORMAT % task

def xapi_task_clear(args, async = False):
    server, session = connect()
    all_tasks = execute(server, 'task.get_all', (session,))
    for task_uuid in all_tasks:
        success = execute(server, 'task.destroy', (session, task_uuid))
        print 'Destroyed Task %s' % task_uuid

def xapi_vm_shutdown(args, async = False):
    opts, args = parse_args("vm-shutdown", args, set_defaults = True)
    
    if len(args) < 1:
        raise OptionError("No Domain name specified.")

    server, session = connect()
    vm_uuid = resolve_vm(server, session, args[0])
    if opts.force:
        print 'Forcefully shutting down VM %s (%s)' % (args[0], vm_uuid)
        success = execute(server, 'VM.hard_shutdown', (session, vm_uuid), async = async)
    else:
        print 'Shutting down VM %s (%s)' % (args[0], vm_uuid)
        success = execute(server, 'VM.clean_shutdown', (session, vm_uuid), async = async)

    if async:
        print 'Task started: %s' % success
    else:
        print 'Done.'

def xapi_vbd_create(args, async = False):
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
    server, session = connect()
    vm_uuid = resolve_vm(server, session, domname)
    cfg['VM'] = vm_uuid
    vbd_uuid = execute(server, 'VBD.create', (session, cfg), async = async)
    if async:
        print 'Task started: %s' % vbd_uuid
    else:
        print 'Done. (%s)' % vbd_uuid

def xapi_vif_create(args, async = False):
    if len(args) < 2:
        raise OptionError("Configuration file not specified")

    domname = args[0]
    filename = args[1]
    cfg = _read_python_cfg(filename)
    
    print 'Creating VIF from %s ..' % filename
    server, session = connect()
    vm_uuid = resolve_vm(server, session, domname)
    cfg['VM'] = vm_uuid
    vif_uuid = execute(server, 'VIF.create', (session, cfg), async = async)
    if async:
        print 'Task started: %s' % vif_uuid
    else:
        print 'Done. (%s)' % vif_uuid

def xapi_vbd_list(args, async = False):
    server, session = connect()
    domname = args[0]
    
    dom_uuid = resolve_vm(server, session, domname)
    vbds = execute(server, 'VM.get_VBDs', (session, dom_uuid))
    
    print VBD_LIST_FORMAT % {'device': 'Device',
                             'uuid' : 'UUID',
                             'VDI': 'VDI'}
    
    for vbd in vbds:
        vbd_struct = execute(server, 'VBD.get_record', (session, vbd))
        print VBD_LIST_FORMAT % vbd_struct
        
        
def xapi_vbd_stats(args, async = False):
    server, session = connect()
    domname = args[0]
    dom_uuid = resolve_vm(server, session, domname)

    vbds = execute(server, 'VM.get_VBDs', (session, dom_uuid))
    for vbd_uuid in vbds:
        print execute(server, 'VBD.get_io_read_kbs', (session, vbd_uuid))
 
def xapi_vif_list(args, async = False):
    server, session = connect()
    opts, args = parse_args('vdi-list', args, set_defaults = True)
    is_long = opts and opts.long
    
    domname = args[0]
    
    dom_uuid = resolve_vm(server, session, domname)
    vifs = execute(server, 'VM.get_VIFs', (session, dom_uuid))

    if not is_long:
        print VIF_LIST_FORMAT % {'name': 'Name',
                                 'device': 'Device',
                                 'uuid' : 'UUID',
                                 'MAC': 'MAC'}
        
        for vif in vifs:
            vif_struct = execute(server, 'VIF.get_record', (session, vif))
            print VIF_LIST_FORMAT % vif_struct
    else:
        for vif in vifs:
            vif_struct = execute(server, 'VIF.get_record', (session, vif))
            pprint(vif_struct)

def xapi_console_list(args, async = False):
    server, session = connect()
    opts, args = parse_args('vdi-list', args, set_defaults = True)
    is_long = opts and opts.long
    
    domname = args[0]
    
    dom_uuid = resolve_vm(server, session, domname)
    consoles = execute(server, 'VM.get_consoles', (session, dom_uuid))

    if not is_long:
        print CONSOLE_LIST_FORMAT % {'protocol': 'Protocol',
                                     'location': 'Location',
                                     'uuid': 'UUID'}

        for console in consoles:
            console_struct = execute(server, 'console.get_record',
                                     (session, console))
            print CONSOLE_LIST_FORMAT % console_struct
    else:
        for console in consoles:
            console_struct = execute(server, 'console.get_record',
                                     (session, console))
            pprint(console_struct)            


def xapi_vdi_list(args, async = False):
    opts, args = parse_args('vdi-list', args, set_defaults = True)
    is_long = opts and opts.long

    server, session = connect()
    vdis = execute(server, 'VDI.get_all', (session,))

    if not is_long:
        print VDI_LIST_FORMAT % {'name_label': 'VDI Label',
                                 'uuid' : 'UUID',
                                 'virtual_size': 'Bytes'}
        
        for vdi in vdis:
            vdi_struct = execute(server, 'VDI.get_record', (session, vdi))
            print VDI_LIST_FORMAT % vdi_struct

    else:
        for vdi in vdis:
            vdi_struct = execute(server, 'VDI.get_record', (session, vdi))
            pprint(vdi_struct)

def xapi_sr_list(args, async = False):
    opts, args = parse_args('sr-list', args, set_defaults = True)
    is_long = opts and opts.long
    
    server, session = connect()
    srs = execute(server, 'SR.get_all', (session,))
    if not is_long:
        print SR_LIST_FORMAT % {'name_label': 'SR Label',
                                'uuid' : 'UUID',
                                'physical_size': 'Size (MB)',
                                'type': 'Type'}
        
        for sr in srs:
            sr_struct = execute(server, 'SR.get_record', (session, sr))
            sr_struct['physical_size'] = int(sr_struct['physical_size'])/MB
            print SR_LIST_FORMAT % sr_struct
    else:
        for sr in srs:
            sr_struct = execute(server, 'SR.get_record', (session, sr))  
            pprint(sr_struct)

def xapi_sr_rename(args, async = False):
    server, session = connect()
    sr = execute(server, 'SR.get_by_name_label', (session, args[0]))
    execute(server, 'SR.set_name_label', (session, sr[0], args[1]))

def xapi_vdi_create(args, async = False):
    opts, args = parse_args('vdi-create', args)

    if len(args) > 0:
        cfg = _read_python_cfg(args[0])
    else:
        cfg = {}
        
    for opt, val in opts:
        cfg[opt] = val

    server, session = connect()
    srs = []
    if cfg.get('SR'):    
        srs = execute(server, 'SR.get_by_name_label', (session, cfg['SR']))
    else:
        srs = execute(server, 'SR.get_all', (session,))

    sr = srs[0]
    cfg['SR'] = sr

    size = cfg['virtual_size']/MB
    print 'Creating VDI of size: %dMB ..' % size,
    uuid = execute(server, 'VDI.create', (session, cfg), async = async)
    if async:
        print 'Task started: %s' % uuid
    else:
        print 'Done. (%s)' % uuid
    

def xapi_vdi_destroy(args, async = False):
    server, session = connect()
    if len(args) < 1:
        raise OptionError('Not enough arguments')

    vdi_uuid = args[0]
    print 'Deleting VDI %s' % vdi_uuid
    result = execute(server, 'VDI.destroy', (session, vdi_uuid), async = async)
    if async:
        print 'Task started: %s' % result
    else:
        print 'Done.'

def xapi_vdi_rename(args, async = False):
    server, session = connect()
    if len(args) < 2:
        raise OptionError('Not enough arguments')

    vdi_uuid = execute(server, 'VDI.get_by_name_label', session, args[0])
    vdi_name = args[1]
    
    print 'Renaming VDI %s to %s' % (vdi_uuid[0], vdi_name)
    result = execute(server, 'VDI.set_name_label',
                     (session, vdi_uuid[0], vdi_name), async = async)
    if async:
        print 'Task started: %s' % result
    else:
        print 'Done.'


def xapi_pif_list(args, async = False):
    server, session = connect()
    pif_uuids = execute(server, 'PIF.get_all', (session,))
    for pif_uuid in pif_uuids:
        pif = execute(server, 'PIF.get_record', (session, pif_uuid))
        print pif


def xapi_debug_wait(args, async = False):
    secs = 10
    if len(args) > 0:
        secs = int(args[0])
    server, session = connect()
    task_uuid = execute(server, 'debug.wait', (session, secs), async=async)
    print 'Task UUID: %s' % task_uuid

def xapi_vm_stat(args, async = False):
    domname = args[0]
    
    server, session = connect()
    vm_uuid = resolve_vm(server, session, domname)
    vif_uuids = execute(server, 'VM.get_VIFs', (session, vm_uuid))
    vbd_uuids = execute(server, 'VM.get_VBDs', (session, vm_uuid))
    vcpus_utils = execute(server, 'VM.get_VCPUs_utilisation',
                          (session, vm_uuid))

    for vcpu_num in sorted(vcpus_utils.keys()):
        print 'CPU %s : %5.2f%%' % (vcpu_num, vcpus_utils[vcpu_num] * 100)
        
    for vif_uuid in vif_uuids:
        vif = execute(server, 'VIF.get_record', (session, vif_uuid))
        print '%(device)s: rx: %(io_read_kbs)10.2f tx: %(io_write_kbs)10.2f' \
              % vif
    for vbd_uuid in vbd_uuids:
        vbd = execute(server, 'VBD.get_record', (session, vbd_uuid))
        print '%(device)s: rd: %(io_read_kbs)10.2f wr: %(io_write_kbs)10.2f' \
              % vbd
        
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
            is_async = 'async' in cmd_name
            if is_async:
                cmd_name = re.sub('async_', '', cmd_name)
                
            func_name = 'xapi_%s' % cmd_name
            func = globals().get(func_name)
            
            if func:
                try:
                    args = tuple(words[1:])
                    func(args, async = is_async)
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
    server, session = connect()
    x = XenAPICmd(server, session)
    x.cmdloop('Xen API Prompt. Type "help" for a list of functions')

def usage(command = None, print_usage = True):
    if not command:
        if print_usage:
            print 'Usage: xapi <subcommand> [options] [args]'
            print
            print 'Subcommands:'
            print

        for func in sorted(globals().keys()):
            if func.startswith('xapi_'):
                command = func[5:].replace('_', '-')
                args, description = COMMANDS.get(command, ('', ''))
                print '%-16s  %-40s' % (command, description)
        print
    else:
        parse_args(command, ['-h'])

def main(args):
    
    # poor man's optparse that doesn't abort on unrecognised opts

    options = {}
    remaining = []
    
    arg_n = 0
    while args:
        arg = args.pop(0)
        
        if arg in ('--help', '-h'):
            options['help'] = True
        elif arg in ('--server', '-s') and args:
            options['server'] = args.pop(0)
        elif arg in ('--user', '-u') and args:
            options['user'] = args.pop(0)
        elif arg in ('--password', '-p') and args:
            options['password'] = args.pop(0)
        else:
            remaining.append(arg)

    # abort here if these conditions are true

    if options.get('help') and not remaining:
        usage()
        sys.exit(1)

    if options.get('help') and remaining:
        usage(remaining[0])
        sys.exit(1)

    if not remaining:
        usage()
        sys.exit(1)

    if options.get('server'):
        # it is ugly to use a global, but it is simple
        global SERVER_URI
        SERVER_URI = options['server']

    if options.get('user'):
        global SERVER_USER
        SERVER_USER = options['user']

    if options.get('password'):
        global SERVER_PASS
        SERVER_PASS = options['password']

    subcmd = remaining[0].replace('-', '_')
    is_async = 'async' in subcmd
    if is_async:
        subcmd = re.sub('async_', '', subcmd)
    subcmd_func_name = 'xapi_' + subcmd
    subcmd_func = globals().get(subcmd_func_name, None)

    if subcmd == 'shell':
        shell()
    elif not subcmd_func or not callable(subcmd_func):
        print 'Error: Unable to find subcommand \'%s\'' % subcmd
        usage()
        sys.exit(1)

    try:
        subcmd_func(remaining[1:], async = is_async)
    except XenAPIError, e:
        print 'Error: %s' % str(e.args[0])
        sys.exit(2)
    except OptionError, e:
        print 'Error: %s' % e

    sys.exit(0)
    
if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
