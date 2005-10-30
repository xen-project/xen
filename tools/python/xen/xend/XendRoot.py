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
Creates the event server and handles configuration.

Other classes get config variables by importing this module,
using instance() to get a XendRoot instance, and then
the config functions (e.g. get_xend_port()) to get
configured values.
"""

import os
import os.path
import string
import sys

import XendLogging
from XendError import XendError

import sxp


class XendRoot:
    """Root of the management classes."""

    """Default path to the config file."""
    config_default = "/etc/xen/xend-config.sxp"

    """Environment variable used to override config_default."""
    config_var     = "XEND_CONFIG"

    """Where network control scripts live."""
    network_script_dir = "/etc/xen/scripts"

    """Where block control scripts live."""
    block_script_dir = "/etc/xen/scripts"

    """Default path to the log file. """
    logfile_default = "/var/log/xend.log"

    """Default level of information to be logged."""
    loglevel_default = 'DEBUG'

    """Default for the flag indicating whether xend should run an http server."""
    xend_http_server_default = 'no'

    """Default interface address xend listens at. """
    xend_address_default      = ''

    """Default for the flag indicating whether xend should run a relocation server."""
    xend_relocation_server_default = 'no'

    """Default interface address the xend relocation server listens at. """
    xend_relocation_address_default = ''

    """Default port xend serves HTTP at. """
    xend_port_default         = '8000'

    """Default port xend serves events at. """
    xend_event_port_default   = '8001'

    """Default port xend serves relocation at. """
    xend_relocation_port_default = '8002'

    """Default for the flag indicating whether xend should run a unix-domain server."""
    xend_unix_server_default = 'yes'

    """Default path the unix-domain server listens at."""
    xend_unix_path_default = '/var/lib/xend/xend-socket'

    dom0_min_mem_default = '0'

    dom0_vcpus_default = '0'

    components = {}

    def __init__(self):
        self.config_path = None
        self.config = None
        self.configure()


    def add_component(self, name, val):
        """Add a xend component.

        @param name: component name
        @param val:  component object
        """
        self.components[name] = val

    def get_component(self, name):
        """Get a xend component from its name.
        This is used as a work-round for problems caused by mutually
        recursive imports.

        @param name: component name
        @return: component object (or None)
        """
        return self.components.get(name)

    def _logError(self, fmt, *args):
        """Logging function to log to stderr. We use this for XendRoot log
        messages because they may be logged before the logger has been
        configured.  Other components can safely use the logger.
        """
        print >>sys.stderr, "xend [ERROR]", fmt % args

    def configure(self):
        self.set_config()
        logfile = self.get_config_value("logfile", self.logfile_default)
        loglevel = self.get_config_value("loglevel", self.loglevel_default)
        XendLogging.init(logfile, level = loglevel)

        from xen.xend.server import params
        if params.XEND_DEBUG:
            XendLogging.addLogStderr()

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

    def get_config(self, name=None):
        """Get the configuration element with the given name, or
        the whole configuration if no name is given.

        @param name: element name (optional)
        @return: config or none
        """
        if name is None:
            val = self.config
        else:
            val = sxp.child(self.config, name)
        return val

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
        except Exception, ex:
            raise XendError("invalid xend config %s: expected int: %s" % (name, v))

    def get_xend_http_server(self):
        """Get the flag indicating whether xend should run an http server.
        """
        return self.get_config_bool("xend-http-server", self.xend_http_server_default)

    def get_xend_relocation_server(self):
        """Get the flag indicating whether xend should run a relocation server.
        """
        return self.get_config_bool("xend-relocation-server", self.xend_relocation_server_default)

    def get_xend_port(self):
        """Get the port xend listens at for its HTTP interface.
        """
        return self.get_config_int('xend-port', self.xend_port_default)

    def get_xend_event_port(self):
        """Get the port xend listens at for connection to its event server.
        """
        return self.get_config_int('xend-event-port', self.xend_event_port_default)

    def get_xend_relocation_port(self):
        """Get the port xend listens at for connection to its relocation server.
        """
        return self.get_config_int('xend-relocation-port', self.xend_relocation_port_default)

    def get_xend_address(self):
        """Get the address xend listens at for its HTTP and event ports.
        This defaults to the empty string which allows all hosts to connect.
        If this is set to 'localhost' only the localhost will be able to connect
        to the HTTP and event ports.
        """
        return self.get_config_value('xend-address', self.xend_address_default)

    def get_xend_relocation_address(self):
        """Get the address xend listens at for its relocation server port.
        This defaults to the empty string which allows all hosts to connect.
        If this is set to 'localhost' only the localhost will be able to connect
        to the HTTP and event ports.
        """
        return self.get_config_value('xend-relocation-address', self.xend_relocation_address_default)

    def get_xend_unix_server(self):
        """Get the flag indicating whether xend should run a unix-domain server.
        """
        return self.get_config_bool("xend-unix-server", self.xend_unix_server_default)

    def get_xend_unix_path(self):
        """Get the path the xend unix-domain server listens at.
        """
        return self.get_config_value("xend-unix-path", self.xend_unix_path_default)

    def get_network_script(self):
        """@return the script used to alter the network configuration when
        Xend starts and stops, or None if no such script is specified."""
        
        s = self.get_config_value('network-script')

        if s:
            result = s.split(" ")
            result[0] = os.path.join(self.network_script_dir, result[0])
            return result
        else:
            return None


    def get_enable_dump(self):
        return self.get_config_bool('enable-dump', 'no')

    def get_vif_script(self):
        return self.get_config_value('vif-script', 'vif-bridge')

    def get_dom0_min_mem(self):
        return self.get_config_int('dom0-min-mem', self.dom0_min_mem_default)

    def get_dom0_vcpus(self):
        return self.get_config_int('dom0-cpus', self.dom0_vcpus_default)

    def get_console_limit(self):
        return self.get_config_int('console-limit', 1024)

def instance():
    """Get an instance of XendRoot.
    Use this instead of the constructor.
    """
    global inst
    try:
        inst
    except:
        inst = XendRoot()
    return inst

def add_component(name, val):
    """Register a component with XendRoot.
    This is used to work-round import cycles.

    @param name: component name
    @param val:  component value (often a module)
    """
    return instance().add_component(name, val)

def get_component(name):
    """Get a component.
    This is used to work-round import cycles.

    @param name: component name
    @return component or None
    """
    return instance().get_component(name)
