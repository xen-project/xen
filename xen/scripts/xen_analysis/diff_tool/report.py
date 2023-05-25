#!/usr/bin/env python3

import os


class ReportError(Exception):
    pass


class Report(object):
    class ReportEntry:
        def __init__(self, file_path, line_number, entry_text, line_id):
            # type: (str, int, list, int) -> None
            if not isinstance(line_number, int) or \
               not isinstance(line_id, int):
                raise ReportError("ReportEntry constructor wrong type args")
            self.file_path = file_path
            self.line_number = line_number
            self.text = entry_text
            self.line_id = line_id

    def __init__(self, report_path):
        # type: (str) -> None
        self.__entries = {}
        self.__path = report_path
        self.__last_line_order = 0

    def parse(self):
        # type: () -> None
        raise ReportError("Please create a specialised class from 'Report'.")

    def get_report_path(self):
        # type: () -> str
        return self.__path

    def get_report_entries(self):
        # type: () -> dict
        return self.__entries

    def add_entry(self, entry_path, entry_line_number, entry_text):
        # type: (str, int, str) -> None
        entry = Report.ReportEntry(entry_path, entry_line_number, entry_text,
                                   self.__last_line_order)
        if entry_path in self.__entries.keys():
            self.__entries[entry_path].append(entry)
        else:
            self.__entries[entry_path] = [entry]
        self.__last_line_order += 1

    def to_list(self):
        # type: () -> list
        report_list = []
        for _, entries in self.__entries.items():
            for entry in entries:
                report_list.append(entry)

        report_list.sort(key=lambda x: x.line_id)
        return report_list

    def __str__(self):
        # type: () -> str
        ret = ""
        for entry in self.to_list():
            ret += entry.file_path + ":" + entry.line_number + ":" + entry.text

        return ret

    def __len__(self):
        # type: () -> int
        return len(self.to_list())

    def __sub__(self, report_b):
        # type: (Report) -> Report
        if self.__class__ != report_b.__class__:
            raise ReportError("Diff of different type of report!")

        filename, file_extension = os.path.splitext(self.__path)
        diff_report = self.__class__(filename + ".diff" + file_extension)
        # Put in the diff report only records of this report that are not
        # present in the report_b.
        for file_path, entries in self.__entries.items():
            rep_b_entries = report_b.get_report_entries()
            if file_path in rep_b_entries.keys():
                # File path exists in report_b, so check what entries of that
                # file path doesn't exist in report_b and add them to the diff
                rep_b_entries_num = [
                    x.line_number for x in rep_b_entries[file_path]
                ]
                for entry in entries:
                    if entry.line_number not in rep_b_entries_num:
                        diff_report.add_entry(file_path, entry.line_number,
                                              entry.text)
            else:
                # File path doesn't exist in report_b, so add every entry
                # of that file path to the diff
                for entry in entries:
                    diff_report.add_entry(file_path, entry.line_number,
                                          entry.text)

        return diff_report
