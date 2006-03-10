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
# Copyright (C) 2005, 2006 XenSource Ltd.
#============================================================================


import tempfile
import types
import logging
import logging.handlers

from xen.xend.server import params


__all__ = [ 'log', 'init', 'getLogFilename' ]


if not 'TRACE' in logging.__dict__:
    logging.TRACE = logging.DEBUG - 1
    logging.addLevelName(logging.TRACE,'TRACE')
    def trace(self, *args, **kwargs):
        self.log(logging.TRACE, *args, **kwargs)
    logging.Logger.trace = trace


log = logging.getLogger("xend")


MAX_BYTES = 1 << 20  # 1MB
BACKUP_COUNT = 5

STDERR_FORMAT = "[%(name)s] %(levelname)s (%(module)s:%(lineno)d) %(message)s"
LOGFILE_FORMAT = "[%(asctime)s %(name)s] %(levelname)s (%(module)s:%(lineno)d) %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


logfilename = None


def init(filename, level):
    """Initialise logging.  Logs to the given filename, and logs to stderr if
    XEND_DEBUG is set.
    """

    global logfilename

    def openFileHandler(fname):
        return logging.handlers.RotatingFileHandler(fname, mode = 'a',
                                                    maxBytes = MAX_BYTES,
                                                    backupCount = BACKUP_COUNT)

    # Rather unintuitively, getLevelName will get the number corresponding to
    # a level name, as well as getting the name corresponding to a level
    # number.  setLevel seems to take the number only though, so convert if we
    # are given a string.
    if isinstance(level, types.StringType):
        level = logging.getLevelName(level)

    log.setLevel(level)

    try:
        fileHandler = openFileHandler(filename)
        logfilename = filename
    except IOError:
        logfilename = tempfile.mkstemp("-xend.log")[1]
        fileHandler = openFileHandler(logfilename)

    fileHandler.setFormatter(logging.Formatter(LOGFILE_FORMAT, DATE_FORMAT))
    log.addHandler(fileHandler)

    if params.XEND_DEBUG:
        stderrHandler = logging.StreamHandler()
        stderrHandler.setFormatter(logging.Formatter(STDERR_FORMAT,
                                                     DATE_FORMAT))
        log.addHandler(stderrHandler)


def getLogFilename():
    return logfilename
