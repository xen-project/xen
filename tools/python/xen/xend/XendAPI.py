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

import inspect
import os
import string
import sys
import traceback

from xen.xend import XendDomain, XendDomainInfo, XendNode
from xen.xend import XendLogging

from xen.xend.XendAuthSessions import instance as auth_manager
from xen.xend.XendError import *
from xen.xend.XendClient import ERROR_INVALID_DOMAIN
from xen.xend.XendLogging import log

from xen.xend.XendAPIConstants import *
from xen.util.xmlrpclib2 import stringify

AUTH_NONE = 'none'
AUTH_PAM = 'pam'

argcounts = {}

# ------------------------------------------
# Utility Methods for Xen API Implementation
# ------------------------------------------

def xen_api_success(value):
    """Wraps a return value in XenAPI format."""
    if value is None:
        s = ''
    else:
        s = stringify(value)
    return {"Status": "Success", "Value": s}

def xen_api_success_void():
    """Return success, but caller expects no return value."""
    return xen_api_success("")

def xen_api_error(error):
    """Wraps an error value in XenAPI format."""
    if type(error) == tuple:
        error = list(error)
    if type(error) != list:
        error = [error]
    if len(error) == 0:
        error = ['INTERNAL_ERROR', 'Empty list given to xen_api_error']

    return { "Status": "Failure",
             "ErrorDescription": [str(x) for x in error] }


def xen_api_todo():
    """Temporary method to make sure we track down all the TODOs"""
    return {"Status": "Error", "ErrorDescription": XEND_ERROR_TODO}

# ---------------------------------------------------
# Python Method Decorators for input value validation
# ---------------------------------------------------

def trace(func, api_name = ''):
    """Decorator to trace XMLRPC Xen API methods.

    @param func: function with any parameters
    @param api_name: name of the api call for debugging.
    """
    if hasattr(func, 'api'):
        api_name = func.api
    def trace_func(self, *args, **kwargs):
        log.debug('%s: %s' % (api_name, args))
        return func(self, *args, **kwargs)
    trace_func.api = api_name
    return trace_func


def catch_typeerror(func):
    """Decorator to catch any TypeErrors and translate them into Xen-API
    errors.

    @param func: function with params: (self, ...)
    @rtype: callable object
    """
    def f(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except TypeError, exn:
            #log.exception('catch_typeerror')
            if hasattr(func, 'api') and func.api in argcounts:
                # Assume that if the exception was thrown inside this
                # file, then it is due to an invalid call from the client,
                # but if it was thrown elsewhere, then it's an internal
                # error (which will be handled further up).
                tb = sys.exc_info()[2]
                try:
                    sourcefile = traceback.extract_tb(tb)[-1][0]
                    if sourcefile == inspect.getsourcefile(XendAPI):
                        return xen_api_error(
                            ['MESSAGE_PARAMETER_COUNT_MISMATCH',
                             func.api, argcounts[func.api],
                             len(args) + len(kwargs)])
                finally:
                    del tb
            raise

    return f


def session_required(func):
    """Decorator to verify if session is valid before calling method.

    @param func: function with params: (self, session, ...)
    @rtype: callable object
    """    
    def check_session(self, session, *args, **kwargs):
        if auth_manager().is_session_valid(session):
            return func(self, session, *args, **kwargs)
        else:
            return xen_api_error(['SESSION_INVALID', session])

    return check_session


def _is_valid_ref(ref, validator):
    return type(ref) == str and validator(ref)

def _check_ref(validator, errcode, func, api, session, ref, *args, **kwargs):
    if _is_valid_ref(ref, validator):
        return func(api, session, ref, *args, **kwargs)
    else:
        return xen_api_error([errcode, ref])


def valid_host(func):
    """Decorator to verify if host_ref is valid before calling method.

    @param func: function with params: (self, session, host_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(XendNode.instance().is_valid_host,
                      'HOST_HANDLE_INVALID', func, *args, **kwargs)

def valid_host_cpu(func):
    """Decorator to verify if host_cpu_ref is valid before calling method.

    @param func: function with params: (self, session, host_cpu_ref, ...)
    @rtype: callable object
    """    
    return lambda *args, **kwargs: \
           _check_ref(XendNode.instance().is_valid_cpu,
                      'HOST_CPU_HANDLE_INVALID', func, *args, **kwargs)

def valid_vm(func):
    """Decorator to verify if vm_ref is valid before calling method.

    @param func: function with params: (self, session, vm_ref, ...)
    @rtype: callable object
    """    
    return lambda *args, **kwargs: \
           _check_ref(XendDomain.instance().is_valid_vm,
                      'VM_HANDLE_INVALID', func, *args, **kwargs)

def valid_network(func):
    """Decorator to verify if network_ref is valid before calling method.

    @param func: function with params: (self, session, network_ref, ...)
    @rtype: callable object
    """    
    return lambda *args, **kwargs: \
           _check_ref(XendNode.instance().is_valid_network,
                      'NETWORK_HANDLE_INVALID', func, *args, **kwargs)

def valid_vbd(func):
    """Decorator to verify if vbd_ref is valid before calling method.

    @param func: function with params: (self, session, vbd_ref, ...)
    @rtype: callable object
    """    
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendDomain.instance().is_valid_dev('vbd', r),
                      'VBD_HANDLE_INVALID', func, *args, **kwargs)

def valid_vif(func):
    """Decorator to verify if vif_ref is valid before calling method.

    @param func: function with params: (self, session, vif_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendDomain.instance().is_valid_dev('vif', r),
                      'VIF_HANDLE_INVALID', func, *args, **kwargs)

def valid_vdi(func):
    """Decorator to verify if vdi_ref is valid before calling method.

    @param func: function with params: (self, session, vdi_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(XendNode.instance().get_sr().is_valid_vdi,
                      'VDI_HANDLE_INVALID', func, *args, **kwargs)

def valid_vtpm(func):
    """Decorator to verify if vtpm_ref is valid before calling method.

    @param func: function with params: (self, session, vtpm_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendDomain.instance().is_valid_dev('vtpm', r),
                      'VTPM_HANDLE_INVALID', func, *args, **kwargs)

def valid_sr(func):
    """Decorator to verify if sr_ref is valid before calling method.

    @param func: function with params: (self, session, sr_ref, ...)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(lambda r: XendNode.instance().get_sr().uuid == r,
                      'SR_HANDLE_INVALID', func, *args, **kwargs)

def valid_pif(func):
    """Decorator to verify if sr_ref is valid before calling
    method.

    @param func: function with params: (self, session, sr_ref)
    @rtype: callable object
    """
    return lambda *args, **kwargs: \
           _check_ref(lambda r: r in XendNode.instance().pifs,
                      'PIF_HANDLE_INVALID', func, *args, **kwargs)

# -----------------------------
# Bridge to Legacy XM API calls
# -----------------------------

def do_vm_func(fn_name, vm_ref, *args, **kwargs):
    """Helper wrapper func to abstract away from repetitive code.

    @param fn_name: function name for XendDomain instance
    @type fn_name: string
    @param vm_ref: vm_ref
    @type vm_ref: string
    @param *args: more arguments
    @type *args: tuple
    """
    try:
        xendom = XendDomain.instance()
        fn = getattr(xendom, fn_name)
        xendom.do_legacy_api_with_uuid(fn, vm_ref, *args, **kwargs)
        return xen_api_success_void()
    except VMBadState, exn:
        return xen_api_error(['VM_BAD_POWER_STATE', vm_ref, exn.expected,
                              exn.actual])


class XendAPI:
    """Implementation of the Xen-API in Xend. Expects to be
    used via XMLRPCServer.

    All methods that need a valid session are marked with
    a L{session_required} decorator that will
    transparently perform the required session authentication.

    We need to support Python <2.4, so we use the old decorator syntax.

    All XMLRPC accessible methods require an 'api' attribute and
    is set to the XMLRPC function name which the method implements.
    """

    def __init__(self, auth):
        self.auth = auth


    Base_attr_ro = ['uuid']
    Base_attr_rw = []
    Base_methods = ['destroy', 'get_by_uuid', 'get_record']
    Base_funcs   = ['create', 'get_all']

    # Xen API: Class Session
    # ----------------------------------------------------------------
    # NOTE: Left unwrapped by __init__

    session_attr_ro = ['this_host', 'this_user']
    session_methods = ['logout']
    # session_funcs = ['login_with_password']    

    def session_login_with_password(self, *args):
        if len(args) != 2:
            return xen_api_error(
                ['MESSAGE_PARAMETER_COUNT_MISMATCH',
                 'session.login_with_password', 2, len(args)])
        username = args[0]
        password = args[1]
        try:
            session = (self.auth == AUTH_NONE and
                       auth_manager().login_unconditionally(username) or
                       auth_manager().login_with_password(username, password))
            return xen_api_success(session)
        except XendError, e:
            return xen_api_error(['SESSION_AUTHENTICATION_FAILED'])
    session_login_with_password.api = 'session.login_with_password'


    # object methods
    def session_logout(self, session):
        auth_manager().logout(session)
        return xen_api_success_void()
    def session_destroy(self, session):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)
    def session_get_record(self, session):
        record = {'this_host': XendNode.instance().uuid,
                  'this_user': auth_manager().get_user(session)}
        return xen_api_success(record)

    # attributes (ro)
    def session_get_this_host(self, session):
        return xen_api_success(XendNode.instance().uuid)
    def session_get_this_user(self, session):
        user = auth_manager().get_user(session)
        if user:
            return xen_api_success(user)
        return xen_api_error(['SESSION_INVALID', session])


    # Xen API: Class User
    # ----------------------------------------------------------------
    # TODO: NOT IMPLEMENTED YET

    # Xen API: Class Tasks
    # ----------------------------------------------------------------
    # TODO: NOT IMPLEMENTED YET    

    # Xen API: Class Host
    # ----------------------------------------------------------------    

    host_attr_ro = ['software_version',
                    'resident_VMs',
                    'host_CPUs']
    
    host_attr_rw = ['name_label',
                    'name_description']

    host_methods = ['disable',
                    'enable',
                    'reboot',
                    'shutdown']
    
    host_funcs = ['get_by_name_label']

    # attributes
    def host_get_name_label(self, session, host_ref):
        return xen_api_success(XendNode.instance().name)
    def host_set_name_label(self, session, host_ref, new_name):
        XendNode.instance().set_name(new_name)
        return xen_api_success_void()
    def host_get_name_description(self, session, host_ref):
        return xen_api_success(XendNode.instance().description)
    def host_set_name_description(self, session, host_ref, new_desc):
        XendNode.instance().set_description(new_desc)
        return xen_api_success_void()
    def host_get_software_version(self, session, host_ref):
        return xen_api_success(XendNode.instance().xen_version())
    def host_get_resident_VMs(self, session, host_ref):
        return xen_api_success(XendDomain.instance().get_domain_refs())
    def host_get_host_CPUs(self, session, host_ref):
        return xen_api_success(XendNode.instance().get_host_cpu_refs())

    # object methods
    def host_destroy(self, session, host_ref):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)    
    def host_disable(self, session, host_ref):
        XendDomain.instance().set_allow_new_domains(False)
        return xen_api_success_void()
    def host_enable(self, session, host_ref):
        XendDomain.instance().set_allow_new_domains(True)
        return xen_api_success_void()
    def host_reboot(self, session, host_ref):
        if not XendDomain.instance().allow_new_domains():
            return xen_api_error(XEND_ERROR_HOST_RUNNING)
        return xen_api_error(XEND_ERROR_UNSUPPORTED)
    def host_shutdown(self, session, host_ref):
        if not XendDomain.instance().allow_new_domains():
            return xen_api_error(XEND_ERROR_HOST_RUNNING)
        return xen_api_error(XEND_ERROR_UNSUPPORTED)        
    def host_get_record(self, session, host_ref):
        node = XendNode.instance()
        dom = XendDomain.instance()
        record = {'uuid': node.uuid,
                  'name_label': node.name,
                  'name_description': '',
                  'software_version': node.xen_version(),
                  'resident_VMs': dom.get_domain_refs(),
                  'host_CPUs': node.get_host_cpu_refs()}
        return xen_api_success(record)

    # class methods
    def host_get_all(self, session):
        return xen_api_success((XendNode.instance().uuid,))
    def host_create(self, session, struct):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)

    # Xen API: Class Host_CPU
    # ----------------------------------------------------------------

    host_cpu_attr_ro = ['host',
                        'number',
                        'features',
                        'utilisation']

    # attributes
    def host_cpu_get_uuid(self, session, host_cpu_ref):
        uuid = XendNode.instance().get_host_cpu_uuid(host_cpu_ref)
        return xen_api_success(uuid)
    def host_cpu_get_host(self, session, host_cpu_ref):
        return xen_api_success(XendNode.instance().uuid)
    def host_cpu_get_features(self, session, host_cpu_ref):
        features = XendNode.instance().get_host_cpu_features(host_cpu_ref)
        return xen_api_success(features)
    def host_cpu_get_utilisation(self, session, host_cpu_ref):
        util = XendNode.instance().get_host_cpu_load(host_cpu_ref)
        return xen_api_success(util)
    def host_cpu_get_number(self, session, host_cpu_ref):
        num = XendNode.instance().get_host_cpu_number(host_cpu_ref)
        return xen_api_success(num)

    # object methods
    def host_cpu_destroy(self, session, host_cpu_ref):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)
    def host_cpu_get_record(self, session, host_cpu_ref):
        node = XendNode.instance()
        record = {'uuid': host_cpu_ref,
                  'host': node.uuid,
                  'number': node.get_host_cpu_number(host_cpu_ref),
                  'features': node.get_host_cpu_features(host_cpu_ref),
                  'utilisation': node.get_host_cpu_load(host_cpu_ref)}
        return xen_api_success(record)

    # class methods
    def host_cpu_get_all(self, session):
        return xen_api_success(XendNode.instance().get_host_cpu_refs())
    def host_cpu_create(self, session, struct):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)


    # Xen API: Class network
    # ----------------------------------------------------------------

    network_attr_ro = ['VIFs', 'PIFs']
    network_attr_rw = ['name_label',
                       'name_description',
                       'default_gateway',
                       'default_netmask']

    def _get_network(self, ref):
        return XendNode.instance().get_network(ref)

    def network_get_all(self, session):
        return xen_api_success(XendNode.instance().get_network_refs())

    def network_get_record(self, session, ref):
        return xen_api_success(
            XendNode.instance().get_network(ref).get_record())

    def network_get_name_label(self, _, ref):
        return xen_api_success(self._get_network(ref).name_label)

    def network_get_name_description(self, _, ref):
        return xen_api_success(self._get_network(ref).name_description)

    def network_get_default_gateway(self, _, ref):
        return xen_api_success(self._get_network(ref).default_gateway)

    def network_get_default_netmask(self, _, ref):
        return xen_api_success(self._get_network(ref).default_netmask)

    def network_get_VIFs(self, _, ref):
        return xen_api_success(self._get_network(ref).get_VIF_UUIDs())

    def network_get_PIFs(self, session, ref):
        return xen_api_success(self._get_network(ref).get_PIF_UUIDs())

    def network_set_name_label(self, _, ref, val):
        return xen_api_success(self._get_network(ref).set_name_label(val))

    def network_set_name_description(self, _, ref, val):
        return xen_api_success(self._get_network(ref).set_name_description(val))

    def network_set_default_gateway(self, _, ref, val):
        return xen_api_success(self._get_network(ref).set_default_gateway(val))

    def network_set_default_netmask(self, _, ref, val):
        return xen_api_success(self._get_network(ref).set_default_netmask(val))


    # Xen API: Class PIF
    # ----------------------------------------------------------------

    PIF_attr_ro = ['io_read_kbs',
                   'io_write_kbs']
    PIF_attr_rw = ['name',
                   'network',
                   'host',
                   'MAC',
                   'MTU',
                   'VLAN']

    PIF_attr_inst = PIF_attr_rw

    def _get_PIF(self, ref):
        return XendNode.instance().pifs[ref]

    # object methods
    def PIF_get_record(self, _, ref):
        return xen_api_success(self._get_PIF(ref).get_record())

    def PIF_get_all(self, _):
        return xen_api_success(XendNode.instance().pifs.keys())

    def PIF_get_name(self, session, ref):
        return xen_api_success(self._get_PIF(ref).name)

    def PIF_get_network(self, session, ref):
        return xen_api_success(self._get_PIF(ref).network.uuid)

    def PIF_get_host(self, session, ref):
        return xen_api_success(self._get_PIF(ref).host.uuid)

    def PIF_get_MAC(self, session, ref):
        return xen_api_success(self._get_PIF(ref).mac)

    def PIF_get_MTU(self, session, ref):
        return xen_api_success(self._get_PIF(ref).mtu)

    def PIF_get_VLAN(self, session, ref):
        return xen_api_success(self._get_PIF(ref).vlan)

    def PIF_get_io_read_kbs(self, session, ref):
        return xen_api_success(self._get_PIF(ref).get_io_read_kbs())

    def PIF_get_io_write_kbs(self, session, ref):
        return xen_api_success(self._get_PIF(ref).get_io_write_kbs())
    
    def PIF_set_name(self, _, ref, name):
        return xen_api_success(self._get_PIF(ref).set_name(name))

    def PIF_set_MAC(self, session, ref, mac):
        return xen_api_success(self._get_PIF(ref).set_mac(name))

    def PIF_set_MTU(self, session, ref, mtu):
        return xen_api_success(self._get_PIF(ref).set_mtu(name))


    # Xen API: Class VM
    # ----------------------------------------------------------------        

    VM_attr_ro = ['power_state',
                  'resident_on',
                  'memory_actual',
                  'memory_static_max',                  
                  'memory_static_min',
                  'VCPUs_number',
                  'VCPUs_utilisation',
                  'VCPUs_features_required',
                  'VCPUs_can_use',
                  'consoles',
                  'VIFs',
                  'VBDs',
                  'VTPMs',
                  'PCI_bus',
                  'tools_version',
                  ]
                  
    VM_attr_rw = ['name_label',
                  'name_description',
                  'user_version',
                  'is_a_template',
                  'auto_power_on',
                  'memory_dynamic_max',
                  'memory_dynamic_min',
                  'VCPUs_policy',
                  'VCPUs_params',
                  'VCPUs_features_force_on',
                  'VCPUs_features_force_off',
                  'actions_after_shutdown',
                  'actions_after_reboot',
                  'actions_after_suspend',
                  'actions_after_crash',
                  'PV_bootloader',
                  'PV_kernel',
                  'PV_ramdisk',
                  'PV_args',
                  'PV_bootloader_args',
                  'HVM_boot',
                  'platform_std_VGA',
                  'platform_serial',
                  'platform_localtime',
                  'platform_clock_offset',
                  'platform_enable_audio',
                  'platform_keymap',
                  'otherConfig']

    VM_methods = ['clone',
                  'start',
                  'pause',
                  'unpause',
                  'clean_shutdown',
                  'clean_reboot',
                  'hard_shutdown',
                  'hard_reboot',
                  'suspend',
                  'resume']
    
    VM_funcs  = ['get_by_name_label']

    # parameters required for _create()
    VM_attr_inst = [
        'name_label',
        'name_description',
        'user_version',
        'is_a_template',
        'memory_static_max',
        'memory_dynamic_max',
        'memory_dynamic_min',
        'memory_static_min',
        'VCPUs_policy',
        'VCPUs_params',
        'VCPUs_features_required',
        'VCPUs_features_can_use',
        'VCPUs_features_force_on',
        'VCPUs_features_force_off',
        'actions_after_shutdown',
        'actions_after_reboot',
        'actions_after_suspend',
        'actions_after_crash',
        'PV_bootloader',
        'PV_kernel',
        'PV_ramdisk',
        'PV_args',
        'PV_bootloader_args',
        'HVM_boot',
        'platform_std_VGA',
        'platform_serial',
        'platform_localtime',
        'platform_clock_offset',
        'platform_enable_audio',
        'platform_keymap',
        'grub_cmdline',
        'PCI_bus',
        'otherConfig']
        
    def VM_get(self, name, session, vm_ref):
        return xen_api_success(
            XendDomain.instance().get_vm_by_uuid(vm_ref).info[name])

    def VM_set(self, name, session, vm_ref, value):
        xd = XendDomain.instance()
        dominfo = xd.get_vm_by_uuid(vm_ref)
        dominfo.info[name] = value
        xd.managed_config_save(dominfo)
        return xen_api_success_void()

    # attributes (ro)
    def VM_get_power_state(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_power_state())
    
    def VM_get_resident_on(self, session, vm_ref):
        return xen_api_success(XendNode.instance().uuid)
    
    def VM_get_memory_actual(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo() # unsupported by xc
    
    def VM_get_memory_static_max(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_memory_static_max())
    
    def VM_get_memory_static_min(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_memory_static_min())
    
    def VM_get_VCPUs_number(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.getVCpuCount())
    
    def VM_get_VCPUs_utilisation(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_vcpus_util())
    
    def VM_get_VCPUs_features_required(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo() # unsupported by xc
    
    def VM_get_VCPUs_can_use(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo() # unsupported by xc
    
    def VM_get_VIFs(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_vifs())
    
    def VM_get_VBDs(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_vbds())
    
    def VM_get_VTPMs(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_vtpms())
    
    def VM_get_PCI_bus(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo() # unsupported by xc
    
    def VM_get_tools_version(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()

    # attributes (rw)
    def VM_get_name_label(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.getName())
    
    def VM_get_name_description(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_user_version(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_is_a_template(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_memory_dynamic_max(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_memory_dynamic_max())

    def VM_get_memory_dynamic_min(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_memory_dynamic_min())        
    
    def VM_get_VCPUs_policy(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo() # need to access scheduler
    
    def VM_get_VCPUs_params(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo() # need access to scheduler
    
    def VM_get_VCPUs_features_force_on(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_VCPUs_features_force_off(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_actions_after_shutdown(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_on_shutdown())
    
    def VM_get_actions_after_reboot(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_on_reboot())
    
    def VM_get_actions_after_suspend(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_on_suspend())
    
    def VM_get_actions_after_crash(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success(dom.get_on_crash())
    
    def VM_get_PV_bootloader(self, session, vm_ref):
        return self.VM_get('PV_bootloader', session, vm_ref)
    
    def VM_get_PV_kernel(self, session, vm_ref):
        return self.VM_get('PV_kernel', session, vm_ref)
    
    def VM_get_PV_ramdisk(self, session, vm_ref):
        return self.VM_get('PV_ramdisk', session, vm_ref)
    
    def VM_get_PV_args(self, session, vm_ref):
        return self.VM_get('PV_args', session, vm_ref)

    def VM_get_PV_bootloader_args(self, session, vm_ref):
        return self.VM_get('PV_bootloader_args', session, vm_ref)

    def VM_get_HVM_boot(self, session, vm_ref):
        return self.VM_get('HVM_boot', session, vm_ref)
    
    def VM_get_platform_std_VGA(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_platform_serial(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_platform_localtime(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_platform_clock_offset(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_platform_enable_audio(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_platform_keymap(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_get_otherConfig(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()

    def VM_set_name_label(self, session, vm_ref, label):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        dom.setName(label)
        return xen_api_success_void()
    
    def VM_set_name_description(self, session, vm_ref, desc):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_user_version(self, session, vm_ref, ver):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_is_a_template(self, session, vm_ref, is_template):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_memory_dynamic_max(self, session, vm_ref, mem):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_memory_dynamic_min(self, session, vm_ref, mem):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_VCPUs_policy(self, session, vm_ref, policy):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_VCPUs_params(self, session, vm_ref, params):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_VCPUs_features_force_on(self, session, vm_ref, features):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_VCPUs_features_force_off(self, session, vm_ref, features):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_actions_after_shutdown(self, session, vm_ref, action):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_actions_after_reboot(self, session, vm_ref, action):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_actions_after_suspend(self, session, vm_ref, action):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_actions_after_crash(self, session, vm_ref, action):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_success_void()

    def VM_set_HVM_boot(self, session, vm_ref, value):
        return self.VM_set('HVM_boot', session, vm_ref, value)

    def VM_set_PV_bootloader(self, session, vm_ref, value):
        return self.VM_set('PV_bootloader', session, vm_ref, value)

    def VM_set_PV_kernel(self, session, vm_ref, value):
        return self.VM_set('PV_kernel', session, vm_ref, value)

    def VM_set_PV_ramdisk(self, session, vm_ref, value):
        return self.VM_set('PV_ramdisk', session, vm_ref, value)

    def VM_set_PV_args(self, session, vm_ref, value):
        return self.VM_set('PV_args', session, vm_ref, value)

    def VM_set_PV_bootloader_args(self, session, vm_ref, value):
        return self.VM_set('PV_bootloader_args', session, vm_ref, value)

    def VM_set_platform_std_VGA(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_platform_serial(self, session, vm_ref, serial):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_platform_localtime(self, session, vm_ref, localtime):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_platform_clock_offset(self, session, vm_ref, clock_offset):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_platform_enable_audio(self, session, vm_ref, enable_audio):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    def VM_set_otherConfig(self, session, vm_ref):
        dom = XendDomain.instance().get_vm_by_uuid(vm_ref)
        return xen_api_todo()
    
    # class methods
    def VM_get_all(self, session):
        refs = [d.get_uuid() for d in XendDomain.instance().list('all')]
        return xen_api_success(refs)
    
    def VM_get_by_name_label(self, session, label):
        xendom = XendDomain.instance()
        dom = xendom.domain_lookup_nr(label)
        if dom:
            return xen_api_success([dom.get_uuid()])
        return xen_api_success([])
    
    def VM_create(self, session, vm_struct):
        xendom = XendDomain.instance()
        domuuid = xendom.create_domain(vm_struct)
        return xen_api_success(domuuid)
    
    # object methods
    def VM_get_record(self, session, vm_ref):
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)
        if not xeninfo:
            return xen_api_error(['VM_HANDLE_INVALID', vm_ref])
        
        record = {
            'uuid': xeninfo.get_uuid(),
            'power_state': xeninfo.get_power_state(),
            'name_label': xeninfo.getName(),
            'name_description': xeninfo.getName(),
            'user_version': 1,
            'is_a_template': False,
            'auto_power_on': False,
            'resident_on': XendNode.instance().uuid,
            'memory_static_min': xeninfo.get_memory_static_min(),
            'memory_static_max': xeninfo.get_memory_static_max(),
            'memory_dynamic_min': xeninfo.get_memory_dynamic_min(),
            'memory_dynamic_max': xeninfo.get_memory_dynamic_max(),
            'memory_actual': xeninfo.get_memory_static_min(),
            'VCPUs_policy': xeninfo.get_vcpus_policy(),
            'VCPUs_params': xeninfo.get_vcpus_params(),
            'VCPUs_number': xeninfo.getVCpuCount(),
            'VCPUs_utilisation': xeninfo.get_vcpus_util(),
            'VCPUs_features_required': [],
            'VCPUs_features_can_use': [],
            'VCPUs_features_force_on': [],
            'VCPUs_features_force_off': [],
            'actions_after_shutdown': xeninfo.get_on_shutdown(),
            'actions_after_reboot': xeninfo.get_on_reboot(),
            'actions_after_suspend': xeninfo.get_on_suspend(),
            'actions_after_crash': xeninfo.get_on_crash(),
            'consoles': xeninfo.get_consoles(),
            'VIFs': xeninfo.get_vifs(),
            'VBDs': xeninfo.get_vbds(),
            'VTPMs': xeninfo.get_vtpms(),
            'PV_bootloader': xeninfo.info.get('PV_bootloader'),
            'PV_kernel': xeninfo.info.get('PV_kernel'),
            'PV_ramdisk': xeninfo.info.get('PV_ramdisk'),
            'PV_args': xeninfo.info.get('PV_args'),
            'PV_bootloader_args': xeninfo.info.get('PV_bootloader_args'),
            'HVM_boot': xeninfo.info.get('HVM_boot'),
            'platform_std_VGA': xeninfo.get_platform_std_vga(),
            'platform_serial': xeninfo.get_platform_serial(),
            'platform_localtime': xeninfo.get_platform_localtime(),
            'platform_clock_offset': xeninfo.get_platform_clock_offset(),
            'platform_enable_audio': xeninfo.get_platform_enable_audio(),
            'platform_keymap': xeninfo.get_platform_keymap(),
            'PCI_bus': xeninfo.get_pci_bus(),
            'tools_version': xeninfo.get_tools_version(),
            'otherConfig': xeninfo.get_other_config()
        }
        return xen_api_success(record)

    def VM_clean_reboot(self, session, vm_ref):
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)
        xeninfo.shutdown("reboot")
        return xen_api_success_void()
    def VM_clean_shutdown(self, session, vm_ref):
        xendom = XendDomain.instance()
        xeninfo = xendom.get_vm_by_uuid(vm_ref)
        xeninfo.shutdown("poweroff")
        return xen_api_success_void()
    def VM_clone(self, session, vm_ref):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)
    def VM_destroy(self, session, vm_ref):
        return do_vm_func("domain_delete", vm_ref)
    def VM_hard_reboot(self, session, vm_ref):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)    
    def VM_hard_shutdown(self, session, vm_ref):
        return do_vm_func("domain_destroy", vm_ref)    
    def VM_pause(self, session, vm_ref):
        return do_vm_func("domain_pause", vm_ref)
    def VM_resume(self, session, vm_ref, start_paused):
        return do_vm_func("domain_resume", vm_ref, start_paused = start_paused)    
    def VM_start(self, session, vm_ref, start_paused):
        return do_vm_func("domain_start", vm_ref, start_paused = start_paused)
    def VM_suspend(self, session, vm_ref):
        return do_vm_func("domain_suspend", vm_ref)    
    def VM_unpause(self, session, vm_ref):
        return do_vm_func("domain_unpause", vm_ref)

    # Xen API: Class VBD
    # ----------------------------------------------------------------
    # Note: accepts a non-API standard 'image' attribute to emulate
    #       regular xm created VBDs

    VBD_attr_ro = ['image',
                   'io_read_kbs',
                   'io_write_kbs']
    VBD_attr_rw = ['VM',
                   'VDI',
                   'device',
                   'mode',
                   'driver']

    VBD_attr_inst = VBD_attr_rw + ['image']

    VBD_methods = ['media_change']

    # object methods
    def VBD_get_record(self, session, vbd_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vbd', vbd_ref)
        if not vm:
            return xen_api_error(['VBD_HANDLE_INVALID', vbd_ref])
        cfg = vm.get_dev_xenapi_config('vbd', vbd_ref)
        if not cfg:
            return xen_api_error(['VBD_HANDLE_INVALID', vbd_ref])

        valid_vbd_keys = self.VBD_attr_ro + self.VBD_attr_rw + \
                         self.Base_attr_ro + self.Base_attr_rw

        return_cfg = {}
        for k in cfg.keys():
            if k in valid_vbd_keys:
                return_cfg[k] = cfg[k]
                
        return xen_api_success(return_cfg)

    def VBD_media_change(self, session, vbd_ref, vdi_ref):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)

    # class methods
    def VBD_create(self, session, vbd_struct):
        xendom = XendDomain.instance()
        if not xendom.is_valid_vm(vbd_struct['VM']):
            return xen_api_error(['VM_HANDLE_INVALID', vbd_struct['VM']])
        
        dom = xendom.get_vm_by_uuid(vbd_struct['VM'])
        vbd_ref = ''
        try:
            if not vbd_struct.get('VDI', None):
                # this is a traditional VBD without VDI and SR 
                vbd_ref = dom.create_vbd(vbd_struct)
            else:
                # new VBD via VDI/SR
                vdi_ref = vbd_struct.get('VDI')
                sr = XendNode.instance().get_sr()
                vdi_image = sr.xen_api_get_by_uuid(vdi_ref)
                if not vdi_image:
                    return xen_api_error(['VDI_HANDLE_INVALID', vdi_ref])
                vdi_image = vdi_image.qcow_path
                vbd_ref = dom.create_vbd_with_vdi(vbd_struct, vdi_image)
        except XendError:
            return xen_api_todo()

        xendom.managed_config_save(dom)
        return xen_api_success(vbd_ref)

    # attributes (rw)
    def VBD_get_VM(self, session, vbd_ref):
        xendom = XendDomain.instance()
        return xen_api_success(xendom.get_dev_property('vbd', vbd_ref, 'VM'))
    
    def VBD_get_VDI(self, session, vbd_ref):
        return xen_api_todo()
    
    def VBD_get_device(self, session, vbd_ref):
        xendom = XendDomain.instance()
        return xen_api_success(xendom.get_dev_property('vbd', vbd_ref,
                                                      'device'))
    def VBD_get_mode(self, session, vbd_ref):
        xendom = XendDomain.instance()
        return xen_api_success(xendom.get_dev_property('vbd', vbd_ref,
                                                      'mode'))
    def VBD_get_driver(self, session, vbd_ref):
        xendom = XendDomain.instance()
        return xen_api_success(xendom.get_dev_property('vbd', vbd_ref,
                                                      'driver'))

    # Xen API: Class VIF
    # ----------------------------------------------------------------

    VIF_attr_ro = ['io_read_kbs',
                   'io_write_kbs']
    VIF_attr_rw = ['name',
                   'type',
                   'device',
                   'network',
                   'VM',
                   'MAC',
                   'MTU']

    VIF_attr_inst = VIF_attr_rw

    # object methods
    def VIF_get_record(self, session, vif_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vif', vif_ref)
        if not vm:
            return xen_api_error(['VIF_HANDLE_INVALID', vif_ref])
        cfg = vm.get_dev_xenapi_config('vif', vif_ref)
        if not cfg:
            return xen_api_error(['VIF_HANDLE_INVALID', vif_ref])
        
        valid_vif_keys = self.VIF_attr_ro + self.VIF_attr_rw + \
                         self.Base_attr_ro + self.Base_attr_rw

        return_cfg = {}
        for k in cfg.keys():
            if k in valid_vif_keys:
                return_cfg[k] = cfg[k]
            
        return xen_api_success(return_cfg)

    # class methods
    def VIF_create(self, session, vif_struct):
        xendom = XendDomain.instance()
        if xendom.is_valid_vm(vif_struct['VM']):
            dom = xendom.get_vm_by_uuid(vif_struct['VM'])
            try:
                vif_ref = dom.create_vif(vif_struct)
                xendom.managed_config_save(dom)                
                return xen_api_success(vif_ref)
            except XendError:
                return xen_api_error(XEND_ERROR_TODO)
        else:
            return xen_api_error(['VM_HANDLE_INVALID', vif_struct['VM']])


    # Xen API: Class VDI
    # ----------------------------------------------------------------
    VDI_attr_ro = ['VBDs',
                   'physical_utilisation',
                   'sector_size',
                   'type',
                   'parent',
                   'children']
    VDI_attr_rw = ['name_label',
                   'name_description',
                   'SR',
                   'virtual_size',
                   'sharable',
                   'read_only']
    VDI_attr_inst = VDI_attr_ro + VDI_attr_rw

    VDI_methods = ['snapshot']
    VDI_funcs = ['get_by_name_label']

    def _get_VDI(self, ref):
        return XendNode.instance().get_sr().xen_api_get_by_uuid(ref)
    
    def VDI_get_VBDs(self, session, vdi_ref):
        return xen_api_todo()
    
    def VDI_get_physical_utilisation(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).
                               get_physical_utilisation())        
    
    def VDI_get_sector_size(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).sector_size)        
    
    def VDI_get_type(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).type)
    
    def VDI_get_parent(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).parent)        
    
    def VDI_get_children(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).children)        
    
    def VDI_get_name_label(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).name_label)

    def VDI_get_name_description(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).name_description)

    def VDI_get_SR(self, session, vdi_ref):
        sr = XendNode.instance().get_sr()
        return xen_api_success(sr.uuid)

    def VDI_get_virtual_size(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).virtual_size)

    def VDI_get_sharable(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).sharable)

    def VDI_get_read_only(self, session, vdi_ref):
        return xen_api_success(self._get_VDI(vdi_ref).read_only)        

    def VDI_set_name_label(self, session, vdi_ref, value):
        self._get_VDI(vdi_ref).name_label = value
        return xen_api_success_void()

    def VDI_set_name_description(self, session, vdi_ref, value):
        self._get_VDI(vdi_ref).name_description = value
        return xen_api_success_void()

    def VDI_set_SR(self, session, vdi_ref, value):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)

    def VDI_set_virtual_size(self, session, vdi_ref, value):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)

    def VDI_set_sharable(self, session, vdi_ref, value):
        self._get_VDI(vdi_ref).sharable = bool(value)
        return xen_api_success_void()
    
    def VDI_set_read_only(self, session, vdi_ref, value):
        self._get_VDI(vdi_ref).read_only = bool(value)
        return xen_api_success_void()

    # Object Methods
    def VDI_snapshot(self, session, vdi_ref):
        return xen_api_todo()
    
    def VDI_destroy(self, session, vdi_ref):
        sr = XendNode.instance().get_sr()
        sr.destroy_image(vdi_ref)
        return xen_api_success_void()

    def VDI_get_record(self, session, vdi_ref):
        sr = XendNode.instance().get_sr()
        image = sr.xen_api_get_by_uuid(vdi_ref)
        return xen_api_success({
            'uuid': vdi_ref,
            'name_label': image.name_label,
            'name_description': image.name_description,
            'SR': sr.uuid,
            'VBDs': [], # TODO
            'virtual_size': image.virtual_size,
            'physical_utilisation': image.physical_utilisation,
            'sector_size': image.sector_size,
            'type': image.type,
            'parent': image.parent,
            'children': image.children,
            'sharable': image.sharable,
            'read_only': image.read_only,
            })

    # Class Functions    
    def VDI_create(self, session, vdi_struct):
        sr = XendNode.instance().get_sr()
        sr_ref = vdi_struct['SR']
        if sr.uuid != sr_ref:
            return xen_api_error(['SR_HANDLE_INVALID', vdi_struct['SR']])

        vdi_uuid = sr.create_image(vdi_struct)
        return xen_api_success(vdi_uuid)

    def VDI_get_all(self, session):
        sr = XendNode.instance().get_sr()
        return xen_api_success(sr.list_images())
    
    def VDI_get_by_name_label(self, session, name):
        sr = XendNode.instance().get_sr()
        image_uuid = sr.xen_api_get_by_name_label(name)
        if image_uuid:
            return xen_api_success([image_uuid])
        return xen_api_success([])


    # Xen API: Class VTPM
    # ----------------------------------------------------------------

    VTPM_attr_rw = [ ]
    VTPM_attr_ro = ['VM',
                    'backend',
                    'instance',
                    'driver']

    VTPM_attr_inst = VTPM_attr_rw

    # object methods
    def VTPM_get_record(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vtpm', vtpm_ref)
        if not vm:
            return xen_api_error(['VTPM_HANDLE_INVALID', vtpm_ref])
        cfg = vm.get_dev_xenapi_config('vtpm', vtpm_ref)
        if not cfg:
            return xen_api_error(['VTPM_HANDLE_INVALID', vtpm_ref])
        valid_vtpm_keys = self.VTPM_attr_ro + self.VTPM_attr_rw + \
                          self.Base_attr_ro + self.Base_attr_rw
        for k in cfg.keys():
            if k not in valid_vtpm_keys:
                del cfg[k]

        return xen_api_success(cfg)

    # Class Functions
    def VTPM_get_instance(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vtpm', vtpm_ref)
        if not vm:
            return xen_api_error(['VTPM_HANDLE_INVALID', vtpm_ref])
        cfg = vm.get_dev_xenapi_config('vtpm', vtpm_ref)
        if not cfg:
            return xen_api_error(['VTPM_HANDLE_INVALID', vtpm_ref])
        if cfg.has_key('instance'):
            instance = cfg['instance']
        else:
            instance = -1
        return xen_api_success(instance)

    def VTPM_get_driver(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vtpm', vtpm_ref)
        if not vm:
            return xen_api_error(['VTPM_HANDLE_INVALID', vtpm_ref])
        cfg = vm.get_dev_xenapi_config('vtpm', vtpm_ref)
        if not cfg:
            return xen_api_error(['VTPM_HANDLE_INVALID', vtpm_ref])
        if cfg.has_key('type'):
            driver = cfg['type']
        else:
            driver = "Unknown"
        return xen_api_success(driver)

    def VTPM_get_backend(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        vm = xendom.get_vm_with_dev_uuid('vtpm', vtpm_ref)
        if not vm:
            return xen_api_error(['VTPM_HANDLE_INVALID', vtpm_ref])
        cfg = vm.get_dev_xenapi_config('vtpm', vtpm_ref)
        if not cfg:
            return xen_api_error(['VTPM_HANDLE_INVALID', vtpm_ref])
        if cfg.has_key('backend'):
            backend = cfg['backend']
        else:
            backend = "Domain-0"
        return xen_api_success(backend)

    def VTPM_get_VM(self, session, vtpm_ref):
        xendom = XendDomain.instance()
        return xen_api_success(xendom.get_dev_property('vtpm', vtpm_ref, 'VM'))

    # class methods
    def VTPM_create(self, session, vtpm_struct):
        xendom = XendDomain.instance()
        if xendom.is_valid_vm(vtpm_struct['VM']):
            dom = xendom.get_vm_by_uuid(vtpm_struct['VM'])
            try:
                vtpm_ref = dom.create_vtpm(vtpm_struct)
                xendom.managed_config_save(dom)
                return xen_api_success(vtpm_ref)
            except XendError:
                return xen_api_error(XEND_ERROR_TODO)
        else:
            return xen_api_error(['VM_HANDLE_INVALID', vtpm_struct['VM']])


    # Xen API: Class SR
    # ----------------------------------------------------------------
    SR_attr_ro = ['VDIs',
                  'virtual_allocation',
                  'physical_utilisation',
                  'physical_size',
                  'type',
                  'location']
    
    SR_attr_rw = ['name_label',
                  'name_description']
    
    SR_attr_inst = ['physical_size',
                    'type',
                    'location',
                    'name_label',
                    'name_description']
    
    SR_methods = ['clone']
    SR_funcs = ['get_by_name_label']

    # Class Functions
    def SR_get_all(self, session):
        sr = XendNode.instance().get_sr()
        return xen_api_success([sr.uuid])

    def SR_get_by_name_label(self, session, label):
        sr = XendNode.instance().get_sr()
        if sr.name_label != label:
            return xen_api_success([])
        return xen_api_success([sr.uuid])

    def SR_create(self, session):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)

    def SR_get_by_uuid(self, session):
        return xen_api_success(XendNode.instance().get_sr().uuid)

    # Class Methods
    def SR_clone(self, session, sr_ref):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)
    
    def SR_destroy(self, session, sr_ref):
        return xen_api_error(XEND_ERROR_UNSUPPORTED)
    
    def SR_get_record(self, session, sr_ref):
        sr = XendNode.instance().get_sr()
        return xen_api_success(sr.get_record())

    # Attribute acceess

    def _get_SR_func(self, _, func, conv = None):
        result = getattr(XendNode.instance().get_sr(), func)()
        if conv:
            result = conv(result)
        return xen_api_success(result)

    def _get_SR_attr(self, _, attr):
        return xen_api_success(str(getattr(XendNode.instance().get_sr(),
                                           attr)))

    def SR_get_VDIs(self, _, ref):
        return self._get_SR_func(ref, 'list_images')

    def SR_get_virtual_allocation(self, _, ref):
        return self._get_SR_func(ref, 'virtual_allocation', str)

    def SR_get_physical_utilisation(self, _, ref):
        return self._get_SR_func(ref, 'used_space_bytes', str)

    def SR_get_physical_size(self, _, ref):
        return self._get_SR_func(ref, 'total_space_bytes', str)
    
    def SR_get_type(self, _, ref):
        return self._get_SR_attr(ref, 'type')

    def SR_get_location(self, _, ref):
        return self._get_SR_attr(ref, 'location')

    def SR_get_name_label(self, _, ref):
        return self._get_SR_attr(ref, 'name_label')
    
    def SR_get_name_description(self, _, ref):
        return self._get_SR_attr(ref, 'name_description')

    def SR_set_name_label(self, session, sr_ref, value):
        sr = XendNode.instance().get_sr()
        sr.name_label = value
        XendNode.instance().save()
        return xen_api_success_void()
    
    def SR_set_name_description(self, session, sr_ref, value):
        sr = XendNode.instance().get_sr()
        sr.name_description = value
        XendNode.instance().save()        
        return xen_api_success_void()


def _decorate():
    """Initialise Xen API wrapper by making sure all functions
    have the correct validation decorators such as L{valid_host}
    and L{session_required}.
    """

    global_validators = [session_required, catch_typeerror]
    classes = {
        'session' : None,
        'host'    : valid_host,
        'host_cpu': valid_host_cpu,
        'network' : valid_network,
        'VM'      : valid_vm,
        'VBD'     : valid_vbd,
        'VIF'     : valid_vif,
        'VDI'     : valid_vdi,
        'VTPM'    : valid_vtpm,
        'SR'      : valid_sr,
        'PIF'     : valid_pif
        }

    # Cheat methods
    # -------------
    # Methods that have a trivial implementation for all classes.
    # 1. get_by_uuid == getting by ref, so just return uuid for
    #    all get_by_uuid() methods.

    for cls in classes.keys():
        get_by_uuid = '%s_get_by_uuid' % cls
        get_uuid = '%s_get_uuid' % cls
        def _get_by_uuid(_1, _2, ref):
            return xen_api_success(ref)

        def _get_uuid(_1, _2, ref):
            return xen_api_success(ref)

        setattr(XendAPI, get_by_uuid, _get_by_uuid)
        setattr(XendAPI, get_uuid,    _get_uuid)

    # 2. get_record is just getting all the attributes, so provide
    #    a fake template implementation.
    # 
    # TODO: ...


    # Wrapping validators around XMLRPC calls
    # ---------------------------------------

    for cls, validator in classes.items():
        def doit(n, takes_instance):
            n_ = n.replace('.', '_')
            try:
                f = getattr(XendAPI, n_)
                argcounts[n] = f.func_code.co_argcount - 1

                validators = takes_instance and validator and [validator] \
                             or []
                validators += global_validators
                for v in validators:
                    f = v(f)
                    f.api = n
                setattr(XendAPI, n_, f)
            except AttributeError:
                log.warn("API call: %s not found" % n)


        ro_attrs = getattr(XendAPI, '%s_attr_ro' % cls, [])
        rw_attrs = getattr(XendAPI, '%s_attr_rw' % cls, [])
        methods  = getattr(XendAPI, '%s_methods' % cls, [])
        funcs    = getattr(XendAPI, '%s_funcs'   % cls, [])

        # wrap validators around readable class attributes
        for attr_name in ro_attrs + rw_attrs + XendAPI.Base_attr_ro:
            doit('%s.get_%s' % (cls, attr_name), True)

        # wrap validators around writable class attrributes
        for attr_name in rw_attrs + XendAPI.Base_attr_rw:
            doit('%s.set_%s' % (cls, attr_name), True)

        # wrap validators around methods
        for method_name in methods + XendAPI.Base_methods:
            doit('%s.%s' % (cls, method_name), True)

        # wrap validators around class functions
        for func_name in funcs + XendAPI.Base_funcs:
            doit('%s.%s' % (cls, func_name), False)

_decorate()


#   
# Auto generate some stubs based on XendAPI introspection
#
if __name__ == "__main__":
    def output(line):
        print '    ' + line
    
    classes = ['VDI', 'SR']
    for cls in classes:
        ro_attrs = getattr(XendAPI, '%s_attr_ro' % cls, [])
        rw_attrs = getattr(XendAPI, '%s_attr_rw' % cls, [])
        methods  = getattr(XendAPI, '%s_methods' % cls, [])
        funcs    = getattr(XendAPI, '%s_funcs' % cls, [])

        ref = '%s_ref' % cls

        for attr_name in ro_attrs + rw_attrs + XendAPI.Base_attr_ro:
            getter_name = '%s_get_%s' % (cls, attr_name)
            output('def %s(self, session, %s):' % (getter_name, ref))
            output('    return xen_api_todo()')

        for attr_name in rw_attrs + XendAPI.Base_attr_rw:
            setter_name = '%s_set_%s' % (cls, attr_name)
            output('def %s(self, session, %s, value):' % (setter_name, ref))
            output('    return xen_api_todo()')

        for method_name in methods + XendAPI.Base_methods:
            method_full_name = '%s_%s' % (cls,method_name)
            output('def %s(self, session, %s):' % (method_full_name, ref))
            output('    return xen_api_todo()')

        for func_name in funcs + XendAPI.Base_funcs:
            func_full_name = '%s_%s' % (cls, func_name)
            output('def %s(self, session):' % func_full_name)
            output('    return xen_api_todo()')
