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
        self.setLevel(level)
        if maxBytes:
            self.maxBytes = maxBytes
        if backupCount:
            self.backupCount = backupCount
        self.initLogFile(filename)
        self.initLogStderr()
        pass

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
        self.logfile = RotatingFileHandler(filename,
                                           mode='a',
                                           maxBytes=self.maxBytes,
                                           backupCount=self.backupCount)
        self.logfile.setFormatter(Formatter(self.logFileFormat, self.dateFormat))
        log = self.getLogger()
        log.addHandler(self.logfile)

    def getLogFile(self):
        return self.logfile

    def initLogStderr(self):
        self.logstderr = StreamHandler()
        self.logstderr.setFormatter(Formatter(self.logStderrFormat, self.dateFormat))
        self.getLogger().addHandler(self.logstderr)
        
    def getLogStderr(self):
        return self.logstderr

log = logging.getLogger("xend")
    
