#!/usr/bin/env python3

import re
from .report import Report, ReportError


class CppcheckReport(Report):
    def __init__(self, report_path):
        # type: (str) -> None
        super(CppcheckReport, self).__init__(report_path)
        # This matches a string like:
        # path/to/file.c(<line number>,<digits>):<whatever>
        # and captures file name path and line number
        # the last capture group is used for text substitution in __str__
        self.__report_entry_regex = re.compile(r'^(.*)\((\d+)(,\d+\):.*)$')

    def parse(self):
        # type: () -> None
        report_path = self.get_report_path()
        try:
            with open(report_path, "rt") as infile:
                report_lines = infile.readlines()
        except OSError as e:
            raise ReportError("Issue with reading file {}: {}"
                              .format(report_path, e))
        for line in report_lines:
            entry = self.__report_entry_regex.match(line)
            if entry and entry.group(1) and entry.group(2):
                file_path = entry.group(1)
                line_number = int(entry.group(2))
                self.add_entry(file_path, line_number, line)
            else:
                raise ReportError("Malformed report entry in file {}:\n{}"
                                  .format(report_path, line))

    def __str__(self):
        # type: () -> str
        ret = ""
        for entry in self.to_list():
            ret += re.sub(self.__report_entry_regex,
                          r'{}({}\3'.format(entry.file_path,
                                            entry.line_number),
                          entry.text)
        return ret
