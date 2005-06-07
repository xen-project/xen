import os

def getenv(var, val, conv=None):
    """Get a value from the environment, with optional conversion.

    @param var  name of environment variable
    @param val  default value
    @param conv conversion function to apply to env value
    @return converted value or default
    """
    try:
        v = os.getenv(var)
        if v is None:
            v = val
        else:
            print var, '=', v
        if conv:
            v = conv(v)
    except:
        v = val
    return v

# The following parameters could be placed in a configuration file.
XEND_PID_FILE      = '/var/run/xend.pid'
XEND_TRACE_FILE    = '/var/log/xend.trace'
XEND_DEBUG_LOG     = '/var/log/xend-debug.log'
XEND_USER          = 'root'
XEND_DEBUG         = getenv("XEND_DEBUG",     0, conv=int)
XEND_DAEMONIZE     = getenv("XEND_DAEMONIZE", not XEND_DEBUG, conv=int)

XENSTORED_PID_FILE = '/var/run/xenstored.pid'
XENSTORED_RUN_DIR  = '/var/run/xenstored'
XENSTORED_LIB_DIR  = '/var/lib/xenstored'
XENSTORED_DEBUG    = getenv("XSDAEMON_DEBUG", 0, conv=int)
