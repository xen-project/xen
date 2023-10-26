#!/usr/bin/env python3

import os, glob, json
from . import settings

class ExclusionFileListError(Exception):
    pass


def cppcheck_exclusion_file_list(input_file):
    ret = []
    excl_list = load_exclusion_file_list(input_file, "xen-analysis")

    for entry in excl_list:
        # Prepending * to the relative path to match every path where the Xen
        # codebase could be
        ret.append("*" + entry[0])

    return ret


# Reads the exclusion file list and returns an array containing a set where the
# first entry is what was listed in the exclusion list file, and the second
# entry is the absolute path of the first entry.
# If the first entry contained a wildcard '*', the second entry will have an
# array of the solved absolute path for that entry.
# Returns [('path',[path,path,...]), ('path',[path,path,...]), ...]
def load_exclusion_file_list(input_file, checker=""):
    ret = []
    try:
        with open(input_file, "rt") as handle:
            content = json.load(handle)
            entries = content['content']
    except json.JSONDecodeError as e:
        raise ExclusionFileListError(
                "JSON decoding error in file {}: {}".format(input_file, e)
        )
    except KeyError:
        raise ExclusionFileListError(
            "Malformed JSON file: content field not found!"
        )
    except Exception as e:
        raise ExclusionFileListError(
                "Can't open file {}: {}".format(input_file, e)
        )

    for entry in entries:
        try:
            path = entry['rel_path']
        except KeyError:
            raise ExclusionFileListError(
                "Malformed JSON entry: rel_path field not found!"
            )
        # Check the checker field
        try:
            entry_checkers = entry['checkers']
        except KeyError:
            # If the field doesn't exists, assume that this entry is for every
            # checker
            entry_checkers = checker

        # Check if this entry is for the selected checker
        if checker not in entry_checkers:
            continue

        abs_path = settings.xen_dir + "/" + path
        check_path = [abs_path]

        # If the path contains wildcards, solve them
        if '*' in abs_path:
            check_path = glob.glob(abs_path)

        # Check that the path exists
        for filepath_object in check_path:
            if not os.path.exists(filepath_object):
                raise ExclusionFileListError(
                    "Malformed path: {} refers to {} that does not exists"
                    .format(path, filepath_object)
                )

        ret.append((path, check_path))

    return ret
