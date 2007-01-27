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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd
#============================================================================

"""Xend root class.
Creates the servers and handles configuration.

Other classes get config variables by importing this module,
using instance() to get a XendOptions instance, and then
the config functions (e.g. get_xend_port()) to get
configured values.
"""

import os
import os.path
import string
import sys

from xen.xend import sxp, osdep, XendLogging
from xen.xend.XendError import XendError

if os.uname()[0] == 'SunOS':
    from xen.lowlevel import scf

class XendOptions:
    """Configuration options."""

    """Where network control scripts live."""
    network_script_dir = osdep.scripts_dir

    """Where block control scripts live."""
    block_script_dir = osdep.scripts_dir

    """Default path to the log file. """
    logfile_default = "/var/log/xen/xend.log"

    """Default level of information to be logged."""
    loglevel_default = 'DEBUG'

    """Default Xen-API server configuration. """
    xen_api_server_default = [['unix']]

    """Default for the flag indicating whether xend should run an http server
    (deprecated)."""
    xend_http_server_default = 'no'

    xend_tcp_xmlrpc_server_default = 'no'

    xend_tcp_xmlrpc_server_address_default = 'localhost'
    
    xend_tcp_xmlrpc_server_port_default = 8006

    xend_unix_xmlrpc_server_default = 'yes'

    """Default interface address xend listens at. """
    xend_address_default      = ''

    """Default for the flag indicating whether xend should run a relocation server."""
    xend_relocation_server_default = 'no'

    """Default interface address the xend relocation server listens at. """
    xend_relocation_address_default = ''

    """Default port xend serves HTTP at. """
    xend_port_default         = 8000

    """Default port xend serves relocation at. """
    xend_relocation_port_default = 8002

    xend_relocation_hosts_allow_default = ''

    """Default for the flag indicating whether xend should run a unix-domain
    server (deprecated)."""
    xend_unix_server_default = 'no'

    """Default external migration tool """
    external_migration_tool_default = ''

    """Default path the unix-domain server listens at."""
    xend_unix_path_default = '/var/lib/xend/xend-socket'

    dom0_min_mem_default = 0

    dom0_vcpus_default = 0

    vncpasswd_default = None

    """Default interface to listen for VNC connections on"""
    xend_vnc_listen_default = '127.0.0.1'

    """Default session storage path."""
    xend_domains_path_default = '/var/lib/xend/domains'

    """Default xend management state storage."""
    xend_state_path_default = '/var/lib/xend/state'

    """Default xend QCoW storage repository location."""
    xend_storage_path_default = '/var/lib/xend/storage'

    """Default type of backend network interfaces"""
    netback_type = osdep.netback_type

    """Default script to configure a backend network interface"""
    vif_script = osdep.vif_script

    def __init__(self):
        self.configure()

    def _logError(self, fmt, *args):
        """Logging function to log to stderr. We use this for XendOptions log
        messages because they may be logged before the logger has been
        configured.  Other components can safely use the logger.
        """
        print >>sys.stderr, "xend [ERROR]", fmt % args


    def configure(self):
        self.set_config()
        XendLogging.init(self.get_config_string("logfile",
                                               self.logfile_default),
                         self.get_config_string("loglevel",
                                               self.loglevel_default))

    def set_config(self):
        raise NotImplementedError()

    def get_config_bool(self, name, val=None):
        raise NotImplementedError()
         
    def get_config_int(self, name, val=None):
        raise NotImplementedError()

    def get_config_string(self, name, val=None):
        raise NotImplementedError()

    def get_xen_api_server(self):
        raise NotImplementedError()

    def get_xend_http_server(self):
        """Get the flag indicating whether xend should run an http server.
        """
        return self.get_config_bool("xend-http-server", self.xend_http_server_default)

    def get_xend_tcp_xmlrpc_server(self):
        return self.get_config_bool("xend-tcp-xmlrpc-server",
                                    self.xend_tcp_xmlrpc_server_default)

    def get_xend_tcp_xmlrpc_server_port(self):
        return self.get_config_int("xend-tcp-xmlrpc-server-port",
                                    self.xend_tcp_xmlrpc_server_port_default)

    def get_xend_tcp_xmlrpc_server_address(self):
        return self.get_config_string("xend-tcp-xmlrpc-server-address",
                                    self.xend_tcp_xmlrpc_server_address_default)    

    def get_xend_unix_xmlrpc_server(self):
        return self.get_config_bool("xend-unix-xmlrpc-server",
                                    self.xend_unix_xmlrpc_server_default)

    def get_xend_relocation_server(self):
        """Get the flag indicating whether xend should run a relocation server.
        """
        return self.get_config_bool("xend-relocation-server",
                                    self.xend_relocation_server_default)

    def get_xend_port(self):
        """Get the port xend listens at for its HTTP interface.
        """
        return self.get_config_int('xend-port', self.xend_port_default)

    def get_xend_relocation_port(self):
        """Get the port xend listens at for connection to its relocation server.
        """
        return self.get_config_int('xend-relocation-port',
                                   self.xend_relocation_port_default)

    def get_xend_relocation_hosts_allow(self):
        return self.get_config_string("xend-relocation-hosts-allow",
                                     self.xend_relocation_hosts_allow_default)

    def get_xend_address(self):
        """Get the address xend listens at for its HTTP port.
        This defaults to the empty string which allows all hosts to connect.
        If this is set to 'localhost' only the localhost will be able to connect
        to the HTTP port.
        """
        return self.get_config_string('xend-address', self.xend_address_default)

    def get_xend_relocation_address(self):
        """Get the address xend listens at for its relocation server port.
        This defaults to the empty string which allows all hosts to connect.
        If this is set to 'localhost' only the localhost will be able to connect
        to the relocation port.
        """
        return self.get_config_string('xend-relocation-address', self.xend_relocation_address_default)

    def get_xend_unix_server(self):
        """Get the flag indicating whether xend should run a unix-domain server.
        """
        return self.get_config_bool("xend-unix-server", self.xend_unix_server_default)

    def get_xend_unix_path(self):
        """Get the path the xend unix-domain server listens at.
        """
        return self.get_config_string("xend-unix-path", self.xend_unix_path_default)

    def get_xend_domains_path(self):
        """ Get the path for persistent domain configuration storage
        """
        return self.get_config_string("xend-domains-path", self.xend_domains_path_default)

    def get_xend_state_path(self):
        """ Get the path for persistent domain configuration storage
        """
        return self.get_config_string("xend-state-path", self.xend_state_path_default)

    def get_xend_storage_path(self):
        """ Get the path for persistent domain configuration storage
        """
        return self.get_config_string("xend-storage-path", self.xend_storage_path_default)        

    def get_network_script(self):
        """@return the script used to alter the network configuration when
        Xend starts and stops, or None if no such script is specified."""
        
        s = self.get_config_string('network-script')

        if s:
            result = s.split(" ")
            result[0] = os.path.join(self.network_script_dir, result[0])
            return result
        else:
            return None

    def get_external_migration_tool(self):
        """@return the name of the tool to handle virtual TPM migration."""
        return self.get_config_string('external-migration-tool', self.external_migration_tool_default)

    def get_enable_dump(self):
        return self.get_config_bool('enable-dump', 'no')

    def get_vif_script(self):
        return self.get_config_string('vif-script', self.vif_script)

    def get_dom0_min_mem(self):
        return self.get_config_int('dom0-min-mem', self.dom0_min_mem_default)

    def get_dom0_vcpus(self):
        return self.get_config_int('dom0-cpus', self.dom0_vcpus_default)

    def get_console_limit(self):
        return self.get_config_int('console-limit', 1024)

    def get_vnclisten_address(self):
        return self.get_config_string('vnc-listen', self.xend_vnc_listen_default)

    def get_vncpasswd_default(self):
        return self.get_config_string('vncpasswd',
                                     self.vncpasswd_default)

class XendOptionsFile(XendOptions):

    """Default path to the config file."""
    config_default = "/etc/xen/xend-config.sxp"

    """Environment variable used to override config_default."""
    config_var     = "XEND_CONFIG"

    def set_config(self):
        """If the config file exists, read it. If not, ignore it.

        The config file is a sequence of sxp forms.
        """
        self.config_path = os.getenv(self.config_var, self.config_default)
        if os.path.exists(self.config_path):
            try:
                fin = file(self.config_path, 'rb')
                try:
                    config = sxp.parse(fin)
                finally:
                    fin.close()
                if config is None:
                    config = ['xend-config']
                else:
                    config.insert(0, 'xend-config')
                self.config = config
            except Exception, ex:
                self._logError('Reading config file %s: %s',
                               self.config_path, str(ex))
                raise
        else:
            self._logError('Config file does not exist: %s',
                           self.config_path)
            self.config = ['xend-config']

    def get_config_value(self, name, val=None):
        """Get the value of an atomic configuration element.

        @param name: element name
        @param val:  default value (optional, defaults to None)
        @return: value
        """
        return sxp.child_value(self.config, name, val=val)

    def get_config_bool(self, name, val=None):
        v = string.lower(str(self.get_config_value(name, val)))
        if v in ['yes', 'y', '1', 'on',  'true',  't']:
            return True
        if v in ['no',  'n', '0', 'off', 'false', 'f']:
            return False
        raise XendError("invalid xend config %s: expected bool: %s" % (name, v))

    def get_config_int(self, name, val=None):
        v = self.get_config_value(name, val)
        try:
            return int(v)
        except Exception:
            raise XendError("invalid xend config %s: expected int: %s" % (name, v))

    def get_config_string(self, name, val=None):
        return self.get_config_value(name, val)

    def get_xen_api_server(self):
        """Get the Xen-API server configuration.
        """
        return self.get_config_value('xen-api-server',
                                     self.xen_api_server_default)

if os.uname()[0] == 'SunOS':
    class XendOptionsSMF(XendOptions):

        def set_config(self):
            pass

        def get_config_bool(self, name, val=None):
            try:
                return scf.get_bool(name)
            except scf.error, e:
                if e[0] == scf.SCF_ERROR_NOT_FOUND:
                    return val
                else:
                    raise XendError("option %s: %s:%s" % (name, e[1], e[2]))

        def get_config_int(self, name, val=None):
            try:
                return scf.get_int(name)
            except scf.error, e:
                if e[0] == scf.SCF_ERROR_NOT_FOUND:
                    return val
                else:
                    raise XendError("option %s: %s:%s" % (name, e[1], e[2]))

        def get_config_string(self, name, val=None):
            try:
                return scf.get_string(name)
            except scf.error, e:
                if e[0] == scf.SCF_ERROR_NOT_FOUND:
                    return val
                else:
                    raise XendError("option %s: %s:%s" % (name, e[1], e[2]))

        def get_xen_api_server(self):
            # When the new server is a supported configuration, we should
            # expand this.
            return [["unix"]]

def instance():
    """Get an instance of XendOptions.
    Use this instead of the constructor.
    """
    global inst
    try:
        inst
    except:
        if os.uname()[0] == 'SunOS':
            inst = XendOptionsSMF()
        else:
            inst = XendOptionsFile()
    return inst
