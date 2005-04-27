# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Xend root class.
Creates the event server and handles configuration.

Other classes get config variables by importing this module,
using instance() to get a XendRoot instance, and then
the config functions (e.g. get_xend_port()) to get
configured values.
"""

import os
import os.path
import sys

import EventServer
from XendLogging import XendLogging
from XendError import XendError

# Initial create of the event server.
eserver = EventServer.instance()

import sxp

class XendRoot:
    """Root of the management classes."""

    """Default path to the root of the database."""
    dbroot_default = "/var/lib/xen/xend-db"

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

    loglevel_default = 'DEBUG'

    """Default for the flag indicating whether xend should run an http server."""
    xend_http_server_default = 'no'

    """Default interface address xend listens at. """
    xend_address_default      = ''

    """Default port xend serves HTTP at. """
    xend_port_default         = '8000'

    """Default port xend serves events at. """
    xend_event_port_default   = '8001'

    """Default for the flag indicating whether xend should run a unix-domain server."""
    xend_unix_server_default = 'yes'

    """Default path the unix-domain server listens at."""
    xend_unix_path_default = '/var/lib/xend/xend-socket'

    """Default interface address xend listens at for consoles."""
    console_address_default   = ''

    """Default port xend serves consoles at. """
    console_port_base_default = '9600'

    components = {}

    def __init__(self):
        self.dbroot = None
        self.config_path = None
        self.config = None
        self.logging = None
        self.configure()
        eserver.subscribe('xend.*', self.event_handler)
        #eserver.subscribe('xend.domain.created', self.event_handler)
        #eserver.subscribe('xend.domain.died', self.event_handler)

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

    def start(self):
        eserver.inject('xend.start', 0)

    def _format(self, msg, args):
        if args:
            return str(msg) % args
        else:
            return str(msg)

    def _log(self, mode, fmt, args):
        """Logging function that uses the logger if it exists, otherwise
        logs to stderr. We use this for XendRoot log messages because
        they may be logged before the logger has been configured.
        Other components can safely use the logger.
        """
        log = self.get_logger()
        if mode not in ['warning', 'info', 'debug', 'error']:
            mode = 'info'
        level = mode.upper()
        if log:
            getattr(log, mode)(fmt, *args)
        else:
            print >>sys.stderr, "xend", "[%s]" % level, self._format(fmt, args)

    def logDebug(self, fmt, *args):
        """Log a debug message.

        @param fmt: message format
        @param args: arguments
        """
        self._log('info', fmt, args)
        
    def logInfo(self, fmt, *args):
        """Log an info message.

        @param fmt: message format
        @param args: arguments
        """
        self._log('info', fmt, args)

    def logWarning(self, fmt, *args):
        """Log a warning message.

        @param fmt: message format
        @param args: arguments
        """
        self._log('warning', fmt, args)
        
    def logError(self, fmt, *args):
        """Log an error message.

        @param fmt: message format
        @param args: arguments
        """
        self._log('error', fmt, args)
        
    def event_handler(self, event, val):
        self.logInfo("EVENT> %s %s", str(event), str(val))

    def configure(self):
        self.set_config()
        self.configure_logger()
        self.dbroot = self.get_config_value("dbroot", self.dbroot_default)

    def configure_logger(self):
        logfile = self.get_config_value("logfile", self.logfile_default)
        loglevel = self.get_config_value("loglevel", self.loglevel_default)
        self.logging = XendLogging(logfile, level=loglevel)
        self.logging.addLogStderr()

    def get_logging(self):
        """Get the XendLogging instance.
        """
        return self.logging

    def get_logger(self):
        """Get the logger.
        """
        return self.logging and self.logging.getLogger()

    def get_dbroot(self):
        """Get the path to the database root.
        """
        return self.dbroot

    def set_config(self):
        """If the config file exists, read it. If not, ignore it.

        The config file is a sequence of sxp forms.
        """
        self.config_path = os.getenv(self.config_var, self.config_default)
        if os.path.exists(self.config_path):
            #self.logInfo('Reading config file %s', self.config_path)
            try:
                fin = file(self.config_path, 'rb')
                try:
                    config = sxp.parse(fin)
                finally:
                    fin.close()
                config.insert(0, 'xend-config')
                self.config = config
            except Exception, ex:
                self.logError('Reading config file %s: %s', self.config_path, str(ex))
                raise
        else:
            self.logError('Config file does not exist: %s', self.config_path)
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
        v = self.get_config_value(name, val)
        if v in ['yes', '1', 'on', 1, True]:
            return True
        if v in ['no', '0', 'off', 0, False]:
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

    def get_xend_port(self):
        """Get the port xend listens at for its HTTP interface.
        """
        return self.get_config_int('xend-port', self.xend_port_default)

    def get_xend_event_port(self):
        """Get the port xend listens at for connection to its event server.
        """
        return self.get_config_int('xend-event-port', self.xend_event_port_default)

    def get_xend_address(self):
        """Get the address xend listens at for its HTTP and event ports.
        This defaults to the empty string which allows all hosts to connect.
        If this is set to 'localhost' only the localhost will be able to connect
        to the HTTP and event ports.
        """
        return self.get_config_value('xend-address', self.xend_address_default)

    def get_xend_unix_server(self):
        """Get the flag indicating whether xend should run a unix-domain server.
        """
        return self.get_config_bool("xend-unix-server", self.xend_unix_server_default)

    def get_xend_unix_path(self):
        """Get the path the xend unix-domain server listens at.
        """
        return self.get_config_value("xend-unix-path", self.xend_unix_path_default)

    def get_console_address(self):
        """Get the address xend listens at for its console ports.
        This defaults to the empty string which allows all hosts to connect.
        If this is set to 'localhost' only the localhost will be able to connect
        to the console ports.
        """
        return self.get_config_value('console-address', self.console_address_default)

    def get_console_port_base(self):
        """Get the base port number used to generate console ports for domains.
        """
        return self.get_config_int('console-port-base', self.console_port_base_default)

    def get_block_script(self, type):
        return self.get_config_value('block-%s' % type, '')

    def get_network_script(self):
        return self.get_config_value('network-script', 'network')

    def get_vif_bridge(self):
        return self.get_config_value('vif-bridge', 'xen-br0')

    def get_vif_script(self):
        return self.get_config_value('vif-script', 'vif-bridge')

    def get_vif_antispoof(self):
        return self.get_config_bool('vif-antispoof', 'yes')

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

def logger():
    """Get the logger.
    """
    return instance().get_logger()

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
