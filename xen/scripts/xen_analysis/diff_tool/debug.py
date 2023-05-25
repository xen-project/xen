#!/usr/bin/env python3

from __future__ import print_function
import os
from .report import Report
from .unified_format_parser import UnifiedFormatParser


class Debug:
    def __init__(self, args):
        self.args = args

    def __get_debug_out_filename(self, path, type):
        # type: (str, str) -> str
        # Take basename
        file_name = os.path.basename(path)
        # Split in name and extension
        file_name = os.path.splitext(file_name)
        if self.args.out != "stdout":
            out_folder = os.path.dirname(self.args.out)
        else:
            out_folder = "./"
        dbg_report_path = out_folder + file_name[0] + type + file_name[1]

        return dbg_report_path

    def __debug_print_report(self, report, type):
        # type: (Report, str) -> None
        report_name = self.__get_debug_out_filename(report.get_report_path(),
                                                    type)
        try:
            with open(report_name, "wt") as outfile:
                print(report, end="", file=outfile)
        except OSError as e:
            print("ERROR: Issue opening file {}: {}".format(report_name, e))

    def debug_print_parsed_report(self, report):
        # type: (Report) -> None
        if not self.args.debug:
            return
        self.__debug_print_report(report, ".parsed")

    def debug_print_patched_report(self, report):
        # type: (Report) -> None
        if not self.args.debug:
            return
        # The patched report contains already .patched in its name
        self.__debug_print_report(report, "")

    def debug_print_parsed_diff(self, diff):
        # type: (UnifiedFormatParser) -> None
        if not self.args.debug:
            return
        diff_filename = diff.get_diff_path()
        out_pathname = self.__get_debug_out_filename(diff_filename, ".parsed")
        try:
            with open(out_pathname, "wt") as outfile:
                for change_obj in diff.get_change_sets().values():
                    print(change_obj, end="", file=outfile)
        except OSError as e:
            print("ERROR: Issue opening file {}: {}".format(out_pathname, e))
