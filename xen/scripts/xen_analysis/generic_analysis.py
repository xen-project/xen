#!/usr/bin/env python3

import os
from . import settings, utils, tag_database, cppcheck_analysis

class ParseTagPhaseError(Exception):
    pass

class BuildPhaseError(Exception):
    pass

class CleanPhaseError(Exception):
    pass


def parse_xen_tags():
    # Load the database for the Xen tags
    subs_list = tag_database.load_tag_database(
        settings.analysis_tool,
        [settings.repo_dir + "/docs/misra/safe.json"]
    )
    subs_list = tag_database.load_tag_database(
        settings.analysis_tool,
        [settings.repo_dir + "/docs/misra/false-positive-{}.json"
                                .format(settings.analysis_tool)],
        subs_list,
        "false-positive"
    )

    # Create outdir if it doesn't exists
    os.makedirs(settings.outdir, exist_ok=True)

    # The following lambda function will return a file if it contains lines with
    # a comment containing "SAF-<number>-{safe|false-positive-<tool>}" on a
    # single line.
    grep_action = lambda x: utils.grep(x,
                                    tag_database.get_xen_tag_comment_regex(
                                                        settings.analysis_tool)
    )
    # Look for a list of .h/.c files that matches the condition above
    parse_file_list = utils.recursive_find_file(settings.xen_dir, r'.*\.[ch]$',
                                                grep_action)

    for entry in parse_file_list:
        file = entry["file"]
        bkp_file = file + ".safparse"
        if os.path.isfile(bkp_file):
            raise ParseTagPhaseError(
                "Found {}, please check the integrity of {}"
                    .format(bkp_file,file)
                )
        os.rename(file, bkp_file)
        time_bkp_file = os.stat(bkp_file)
        # Create <file> from <file>.safparse but with the Xen tag parsed
        try:
            tag_database.substitute_tags(settings.analysis_tool, bkp_file, entry,
                                         subs_list)
        except Exception as e:
            raise ParseTagPhaseError("{}".format(e))
        finally:
            # Set timestamp for file equal to bkp_file, so that if the file is
            # modified during the process by the user, we can catch it
            os.utime(file, (time_bkp_file.st_atime, time_bkp_file.st_mtime))


def build_xen():
    utils.invoke_command(
            "make -C {} {} {} build"
                .format(settings.xen_dir, settings.make_forward_args,
                        cppcheck_analysis.cppcheck_extra_make_args),
            False, BuildPhaseError,
            "Build error occured when running:\n{}"
        )


def clean_analysis_artifacts():
    safparse_files = utils.recursive_find_file(settings.xen_dir,
                                               r'.*.safparse$')
    for original_file in safparse_files:
        # This commands strips the .safparse extension, leaving <file>
        parsed_file_path = os.path.splitext(original_file)[0]
        mtime_original_file = os.stat(original_file).st_mtime
        mtime_parsed_file = os.stat(parsed_file_path).st_mtime
        if mtime_original_file != mtime_parsed_file:
            return CleanPhaseError(
                    "The file {} was modified during the analysis "
                    "procedure, it is impossible now to restore from the "
                    "content of {}, please handle it manually"
                    .format(parsed_file_path, original_file)
                )
        # Replace <file>.safparse to <file>
        os.replace(original_file, parsed_file_path)
