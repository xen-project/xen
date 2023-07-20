#!/usr/bin/env python3

import re
import sys

try:
    from enum import Enum
except Exception:
    if sys.version_info[0] == 2:
        print("Please install enum34 package when using python 2.")
    else:
        print("Please use python version 3.5 or above.")
    sys.exit(1)

try:
    from typing import Tuple
except Exception:
    if sys.version_info[0] == 2:
        print("Please install typing package when using python 2.")
    else:
        print("Please use python version 3.5 or above.")
    sys.exit(1)


class UnifiedFormatParseError(Exception):
    pass


class ParserState(Enum):
    FIND_DIFF_HEADER = 0
    REGISTER_CHANGES = 1
    FIND_HUNK_OR_DIFF_HEADER = 2


class ChangeSet(object):
    class ChangeType(Enum):
        REMOVE = 0
        ADD = 1

    class ChangeMode(Enum):
        NONE = 0
        CHANGE = 1
        RENAME = 2
        DELETE = 3
        COPY = 4

    def __init__(self, a_file, b_file):
        # type: (str, str) -> None
        self.orig_file = a_file
        self.dst_file = b_file
        self.change_mode = ChangeSet.ChangeMode.NONE
        self.__changes = []

    def __str__(self):
        # type: () -> str
        str_out = "{}: {} -> {}:\n{}\n".format(
            str(self.change_mode), self.orig_file, self.dst_file,
            str(self.__changes)
        )
        return str_out

    def set_change_mode(self, change_mode):
        # type: (ChangeMode) -> None
        self.change_mode = change_mode

    def is_change_mode(self, change_mode):
        # type: (ChangeMode) -> bool
        return self.change_mode == change_mode

    def add_change(self, line_number, change_type):
        # type: (int, ChangeType) -> None
        self.__changes.append((line_number, change_type))

    def get_change_set(self):
        # type: () -> dict
        return self.__changes


class UnifiedFormatParser(object):
    def __init__(self, args):
        # type: (str | list) -> None
        if isinstance(args, str):
            self.__diff_file = args
            try:
                with open(self.__diff_file, "rt") as infile:
                    self.__diff_lines = infile.readlines()
            except OSError as e:
                raise UnifiedFormatParseError(
                    "Issue with reading file {}: {}"
                    .format(self.__diff_file, e)
                )
        elif isinstance(args, list):
            self.__diff_file = "git-diff-local.txt"
            self.__diff_lines = args
        else:
            raise UnifiedFormatParseError(
                "UnifiedFormatParser constructor called with wrong arguments")

        self.__git_diff_header = re.compile(r'^diff --git a/(.*) b/(.*)$')
        self.__git_hunk_header = \
            re.compile(r'^@@ -\d+,(\d+) \+(\d+),(\d+) @@.*$')
        self.__diff_set = {}
        self.__parse()

    def get_diff_path(self):
        # type: () -> str
        return self.__diff_file

    def add_change_set(self, change_set):
        # type: (ChangeSet) -> None
        if not change_set.is_change_mode(ChangeSet.ChangeMode.NONE):
            if change_set.is_change_mode(ChangeSet.ChangeMode.COPY):
                # Add copy change mode items using the dst_file key, because
                # there might be other changes for the orig_file in this diff
                self.__diff_set[change_set.dst_file] = change_set
            else:
                self.__diff_set[change_set.orig_file] = change_set

    def __parse(self):
        # type: () -> None
        def parse_diff_header(line):
            # type: (str) -> ChangeSet | None
            change_item = None
            diff_head = self.__git_diff_header.match(line)
            if diff_head and diff_head.group(1) and diff_head.group(2):
                change_item = ChangeSet(diff_head.group(1), diff_head.group(2))

            return change_item

        def parse_hunk_header(line):
            # type: (str) -> Tuple[int, int, int]
            file_linenum = -1
            hunk_a_linemax = -1
            hunk_b_linemax = -1
            hunk_head = self.__git_hunk_header.match(line)
            if hunk_head and hunk_head.group(1) and hunk_head.group(2) \
               and hunk_head.group(3):
                file_linenum = int(hunk_head.group(2))
                hunk_a_linemax = int(hunk_head.group(1))
                hunk_b_linemax = int(hunk_head.group(3))

            return (file_linenum, hunk_a_linemax, hunk_b_linemax)

        file_linenum = 0
        hunk_a_linemax = 0
        hunk_b_linemax = 0
        consecutive_remove = 0
        diff_elem = None
        parse_state = ParserState.FIND_DIFF_HEADER
        ChangeMode = ChangeSet.ChangeMode
        ChangeType = ChangeSet.ChangeType

        for line in self.__diff_lines:
            if parse_state == ParserState.FIND_DIFF_HEADER:
                diff_elem = parse_diff_header(line)
                if diff_elem:
                    # Found the diff header, go to the next stage
                    parse_state = ParserState.FIND_HUNK_OR_DIFF_HEADER
            elif parse_state == ParserState.FIND_HUNK_OR_DIFF_HEADER:
                # Here only these change modalities will be registered:
                # deleted file mode <mode>
                # rename from <path>
                # rename to <path>
                # copy from <path>
                # copy to <path>
                #
                # These will be ignored:
                # old mode <mode>
                # new mode <mode>
                # new file mode <mode>
                #
                # Also these info will be ignored
                # similarity index <number>
                # dissimilarity index <number>
                # index <hash>..<hash> <mode>
                if line.startswith("deleted file"):
                    # If the file is deleted, register it but don't go through
                    # the changes that will be only a set of lines removed
                    diff_elem.set_change_mode(ChangeMode.DELETE)
                    parse_state = ParserState.FIND_DIFF_HEADER
                elif line.startswith("new file"):
                    # If the file is new, skip it, as it doesn't give any
                    # useful information on the report translation
                    parse_state = ParserState.FIND_DIFF_HEADER
                elif line.startswith("rename to"):
                    # Renaming operation can be a pure renaming or a rename
                    # and a set of change, so keep looking for the hunk
                    # header
                    diff_elem.set_change_mode(ChangeMode.RENAME)
                elif line.startswith("copy to"):
                    # This is a copy operation, mark it
                    diff_elem.set_change_mode(ChangeMode.COPY)
                else:
                    # Look for the hunk header
                    (file_linenum, hunk_a_linemax, hunk_b_linemax) = \
                        parse_hunk_header(line)
                    if file_linenum >= 0:
                        if diff_elem.is_change_mode(ChangeMode.NONE):
                            # The file has only changes
                            diff_elem.set_change_mode(ChangeMode.CHANGE)
                        parse_state = ParserState.REGISTER_CHANGES
                    else:
                        # ... or there could be a diff header
                        new_diff_elem = parse_diff_header(line)
                        if new_diff_elem:
                            # Found a diff header, register the last change
                            # item
                            self.add_change_set(diff_elem)
                            diff_elem = new_diff_elem
            elif parse_state == ParserState.REGISTER_CHANGES:
                if (hunk_b_linemax > 0) and line.startswith("+"):
                    diff_elem.add_change(file_linenum, ChangeType.ADD)
                    hunk_b_linemax -= 1
                    consecutive_remove = 0
                elif (hunk_a_linemax > 0) and line.startswith("-"):
                    diff_elem.add_change(file_linenum + consecutive_remove,
                                         ChangeType.REMOVE)
                    hunk_a_linemax -= 1
                    file_linenum -= 1
                    consecutive_remove += 1
                elif ((hunk_a_linemax + hunk_b_linemax) > 0) and \
                        line.startswith(" "):
                    hunk_a_linemax -= 1 if (hunk_a_linemax > 0) else 0
                    hunk_b_linemax -= 1 if (hunk_b_linemax > 0) else 0
                    consecutive_remove = 0

                if (hunk_a_linemax + hunk_b_linemax) <= 0:
                    parse_state = ParserState.FIND_HUNK_OR_DIFF_HEADER

                file_linenum += 1

        if diff_elem is not None:
            self.add_change_set(diff_elem)

    def get_change_sets(self):
        # type: () -> dict
        return self.__diff_set
