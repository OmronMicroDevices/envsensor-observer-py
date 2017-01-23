#!/usr/bin/python

# csv logger class ############################################################
from logging.handlers import TimedRotatingFileHandler


class CSVHandler(TimedRotatingFileHandler):
    def __init__(self, logfile, when, interval):
        super(CSVHandler, self).\
            __init__(logfile, when, interval)
        self._header = ""
        self._log = None

    def doRollover(self):
        super(CSVHandler, self).doRollover()
        if self._log is not None and self._header != "":
            self._log.info(self._header)

    def setHeader(self, header):
        self._header = header

    def configureHeaderWriter(self, header, log):
        self._header = header
        self._log = log
