#!/usr/bin/env python3

import os
from .unified_format_parser import UnifiedFormatParser, ChangeSet


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

    def remove_entries(self, entry_file_path):
        # type: (str) -> None
        del self.__entries[entry_file_path]

    def remove_entry(self, entry_path, line_id):
        # type: (str, int) -> None
        if entry_path in self.__entries.keys():
            len_entry_path = len(self.__entries[entry_path])
            if len_entry_path == 1:
                del self.__entries[entry_path]
            else:
                if line_id in self.__entries[entry_path]:
                    self.__entries[entry_path].remove(line_id)

    def patch(self, diff_obj):
        # type: (UnifiedFormatParser) -> Report
        filename, file_extension = os.path.splitext(self.__path)
        patched_report = self.__class__(filename + ".patched" + file_extension)
        remove_files = []
        rename_files = []
        remove_entry = []
        ChangeMode = ChangeSet.ChangeMode

        # Copy entries from this report to the report we are going to patch
        for entries in self.__entries.values():
            for entry in entries:
                patched_report.add_entry(entry.file_path, entry.line_number,
                                         entry.text)

        # Patch the output report
        patched_rep_entries = patched_report.get_report_entries()
        for file_diff, change_obj in diff_obj.get_change_sets().items():
            if change_obj.is_change_mode(ChangeMode.COPY):
                # Copy the original entry pointed by change_obj.orig_file into
                # a new key in the patched report named change_obj.dst_file,
                # that here is file_diff variable content, because this
                # change_obj is pushed into the change_sets with the
                # change_obj.dst_file key
                if change_obj.orig_file in self.__entries.keys():
                    for entry in self.__entries[change_obj.orig_file]:
                        patched_report.add_entry(file_diff,
                                                 entry.line_number,
                                                 entry.text)

            if file_diff in patched_rep_entries.keys():
                if change_obj.is_change_mode(ChangeMode.DELETE):
                    # No need to check changes here, just remember to delete
                    # the file from the report
                    remove_files.append(file_diff)
                    continue
                elif change_obj.is_change_mode(ChangeMode.RENAME):
                    # Remember to rename the file entry on this report
                    rename_files.append(change_obj)

                for line_num, change_type in change_obj.get_change_set():
                    len_rep = len(patched_rep_entries[file_diff])
                    for i in range(len_rep):
                        rep_item = patched_rep_entries[file_diff][i]
                        if change_type == ChangeSet.ChangeType.REMOVE:
                            if rep_item.line_number == line_num:
                                # This line is removed with this changes,
                                # append to the list of entries to be removed
                                remove_entry.append(rep_item)
                            elif rep_item.line_number > line_num:
                                rep_item.line_number -= 1
                        elif change_type == ChangeSet.ChangeType.ADD:
                            if rep_item.line_number >= line_num:
                                rep_item.line_number += 1
                    # Remove deleted entries from the list
                    if len(remove_entry) > 0:
                        for entry in remove_entry:
                            patched_report.remove_entry(entry.file_path,
                                                        entry.line_id)
                        del remove_entry[:]

        if len(remove_files) > 0:
            for file_name in remove_files:
                patched_report.remove_entries(file_name)

        if len(rename_files) > 0:
            for change_obj in rename_files:
                patched_rep_entries[change_obj.dst_file] = \
                    patched_rep_entries.pop(change_obj.orig_file)

        return patched_report

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
