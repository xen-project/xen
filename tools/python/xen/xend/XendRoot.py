# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Xend root class.
Creates the event server and handles configuration.
"""

import os
import os.path
import sys

import EventServer
from XendLogging import XendLogging

# Initial create of the event server.
eserver = EventServer.instance()

import sxp

def reboots():
    """Get a list of system reboots from wtmp.
    """
    out = os.popen('last reboot', 'r')
    list = [ x.strip() for x in out if x.startswith('reboot') ]
    return list

def last_reboot():
    """Get the last known system reboot.
    """
    l = reboots()
    return (l and l[-1]) or None

class XendRoot:
    """Root of the management classes."""

    lastboot_default = "/var/xen/lastboot"

    """Default path to the root of the database."""
    dbroot_default = "/var/xen/xend-db"

    """Default path to the config file."""
    config_default = "/etc/xen/xend-config.sxp"

    """Environment variable used to override config_default."""
    config_var     = "XEND_CONFIG"

    """Where network control scripts live."""
    network_script_dir = "/etc/xen/scripts"

    """Where block control scripts live."""
    block_script_dir = "/etc/xen/scripts"

    logfile_default = "/var/log/xend.log"

    loglevel_default = 'DEBUG'

    components = {}

    def __init__(self):
        self.rebooted = 0
        self.last_reboot = None
        self.dbroot = None
        self.config_path = None
        self.config = None
        self.logger = None
        self.configure()
        self.check_lastboot()
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
        eserver.inject('xend.start', self.rebooted)

    def _format(self, msg, args):
        if args:
            return str(msg)
        else:
            return str(msg) % args

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
            print >>stderr, "xend", "[%s]" % level, self._format(msg, args)

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

    def read_lastboot(self):
        """Read the lastboot file to determine the time of the last boot.
        """
        try:
            val = file(self.lastboot, 'rb').readlines()[0]
        except StandardError, ex:
            self.logWarning('Error reading %s: %s', self.lastboot, str(ex))
            val = None
        return val

    def write_lastboot(self, val):
        """Write the last boot time to the lastboot file.
        """
        if not val: return
        try:
            fdir = os.path.dirname(self.lastboot)
            if not os.path.isdir(fdir):
                os.makedirs(fdir)
            out = file(self.lastboot, 'wb+')
            out.write(val)
            out.close()
        except IOError, ex:
            self.logWarning('Error writing %s: %s', self.lastboot, str(ex))

    def check_lastboot(self):
        """Check if there has been a system reboot since we saved lastboot.
        """
        last_val = self.read_lastboot()
        this_val = last_reboot()
        if this_val == last_val:
            self.rebooted = 0
        else:
            self.rebooted = 1
            self.write_lastboot(this_val)
        self.last_reboot = this_val

    def get_last_reboot(self):
        """Get the last reboot time as a string.
        """
        return self.last_reboot

    def get_rebooted(self):
        """Get the rebooted flag. The flag is true if the system has
        been rebooted since xend was last run.
        """
        return self.rebooted

    def configure(self):
        self.set_config()
        self.configure_logger()
        self.dbroot = self.get_config_value("dbroot", self.dbroot_default)
        self.lastboot = self.get_config_value("lastboot", self.lastboot_default)

    def configure_logger(self):
        logfile = self.get_config_value("logfile", self.logfile_default)
        loglevel = self.get_config_value("loglevel", self.loglevel_default)
        self.logging = XendLogging(logfile, level=loglevel)

    def get_logging(self):
        """Get the XendLogging instance.
        """
        return self.logging

    def get_logger(self):
        """Get the logger.
        """
        return self.logging.getLogger()

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
            fin = file(self.config_path, 'rb')
            try:
                config = sxp.parse(fin)
                config.insert(0, 'xend-config')
                self.config = config
            finally:
                fin.close()
        else:
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

    def get_xend_port(self):
        return int(self.get_config_value('xend-port', '8000'))

    def get_xend_address(self):
        return self.get_config_value('xend-address', '')

    def get_block_script(self, type):
        return self.get_config_value('block-%s' % type, '')

    def get_network_script(self):
        return self.get_config_value('network-script', 'network')

    def get_vif_bridge(self):
        return self.get_config_value('vif-bridge', 'xen-br0')

    def get_vif_script(self):
        return self.get_config_value('vif-script', 'vif-bridge')

    def get_vif_antispoof(self):
        v = self.get_config_value('vif-antispoof', 'yes')
        return v in ['yes', '1', 'on']

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
