# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import types
import logging
from logging import Formatter, StreamHandler
from logging.handlers import RotatingFileHandler

class XendLogging:

    KB = 1024
    MB = 1024 * KB
    
    maxBytes = 1 * MB
    backupCount = 5

    logStderrFormat = "[%(name)s] %(levelname)s (%(module)s:%(lineno)d) %(message)s"
    logFileFormat   = "[%(asctime)s %(name)s] %(levelname)s (%(module)s:%(lineno)d) %(message)s"
    dateFormat = "%Y-%m-%d %H:%M:%S"

    def __init__(self, filename, level=logging.INFO, maxBytes=None, backupCount=None):
        """Initialise logging. Logs to 'filename' by default, but does not log to
        stderr unless addLogStderr() is called.
        """
        self.setLevel(level)
        if maxBytes:
            self.maxBytes = maxBytes
        if backupCount:
            self.backupCount = backupCount
        self.initLogFile(filename)
        self.initLogStderr()

    def setLevel(self, level):
        if isinstance(level, types.StringType):
            level = logging._levelNames[level]
        self.getLogger().setLevel(level)
        self.level = level

    def getLevel(self, level):
        return logging.getLevelName(self.level)

    def getLogger(self):
        return logging.getLogger("xend")

    def initLogFile(self, filename):
        """Create the file logger and add it.
        """
        self.logfile = RotatingFileHandler(filename,
                                           mode='a',
                                           maxBytes=self.maxBytes,
                                           backupCount=self.backupCount)
        self.logfilename = filename
        self.logfile.setFormatter(Formatter(self.logFileFormat, self.dateFormat))
        log = self.getLogger()
        log.addHandler(self.logfile)

    def getLogFile(self):
        return self.logfile

    def getLogFilename(self):
        return self.logfilename

    def initLogStderr(self):
        """Create the stderr logger, but don't add it.
        """
        self.logstderr = StreamHandler()
        self.logstderr.setFormatter(Formatter(self.logStderrFormat, self.dateFormat))

    def addLogStderr(self):
        """Add logging to stderr."""
        self.getLogger().addHandler(self.logstderr)

    def removeLogStderr(self):
        """Remove logging to stderr."""
        self.getLogger().removeHandler(self.logstderr)
        
    def getLogStderr(self):
        return self.logstderr

log = logging.getLogger("xend")
    
