#!/usr/bin/env python3

from __future__ import print_function
import os
import sys
from argparse import ArgumentParser
from xen_analysis.diff_tool.cppcheck_report import CppcheckReport
from xen_analysis.diff_tool.debug import Debug
from xen_analysis.diff_tool.report import ReportError
from xen_analysis.diff_tool.unified_format_parser import \
    (UnifiedFormatParser, UnifiedFormatParseError)
from xen_analysis.settings import repo_dir
from xen_analysis.utils import invoke_command


class DiffReportError(Exception):
    pass


def log_info(text, end='\n'):
    # type: (str, str) -> None
    global args
    global file_out

    if (args.verbose):
        print(text, end=end, file=file_out)


def main(argv):
    # type: (list) -> None
    global args
    global file_out

    parser = ArgumentParser(prog="diff-report.py")
    parser.add_argument("-b", "--baseline", required=True, type=str,
                        help="Path to the baseline report.")
    parser.add_argument("--debug", action='store_true',
                        help="Produce intermediate reports during operations.")
    parser.add_argument("-o", "--out", default="stdout", type=str,
                        help="Where to print the tool output. Default is "
                             "stdout")
    parser.add_argument("-r", "--report", required=True, type=str,
                        help="Path to the 'check report', the one checked "
                             "against the baseline.")
    parser.add_argument("-v", "--verbose", action='store_true',
                        help="Print more informations during the run.")
    parser.add_argument("--patch", type=str,
                        help="The patch file containing the changes to the "
                             "code, from the baseline analysis result to the "
                             "'check report' analysis result.\n"
                             "Do not use with --baseline-rev/--report-rev")
    parser.add_argument("--baseline-rev", type=str,
                        help="Revision or SHA of the codebase analysed to "
                             "create the baseline report.\n"
                             "Use together with --report-rev")
    parser.add_argument("--report-rev", type=str,
                        help="Revision or SHA of the codebase analysed to "
                             "create the 'check report'.\n"
                             "Use together with --baseline-rev")

    args = parser.parse_args()

    if args.patch and (args.baseline_rev or args.report_rev):
        print("ERROR: '--patch' argument can't be used with '--baseline-rev'"
              " or '--report-rev'.")
        sys.exit(1)

    if bool(args.baseline_rev) != bool(args.report_rev):
        print("ERROR: '--baseline-rev' must be used together with "
              "'--report-rev'.")
        sys.exit(1)

    if args.out == "stdout":
        file_out = sys.stdout
    else:
        try:
            file_out = open(args.out, "wt")
        except OSError as e:
            print("ERROR: Issue opening file {}: {}".format(args.out, e))
            sys.exit(1)

    debug = Debug(args)

    try:
        baseline_path = os.path.realpath(args.baseline)
        log_info("Loading baseline report {}".format(baseline_path), "")
        baseline = CppcheckReport(baseline_path)
        baseline.parse()
        debug.debug_print_parsed_report(baseline)
        log_info(" [OK]")
        new_rep_path = os.path.realpath(args.report)
        log_info("Loading check report {}".format(new_rep_path), "")
        new_rep = CppcheckReport(new_rep_path)
        new_rep.parse()
        debug.debug_print_parsed_report(new_rep)
        log_info(" [OK]")
        diff_source = None
        if args.patch:
            diff_source = os.path.realpath(args.patch)
        elif args.baseline_rev:
            git_diff = invoke_command(
                "git --git-dir={}/.git diff -C -C {}..{}"
                .format(repo_dir, args.baseline_rev, args.report_rev),
                True, DiffReportError, "Error occured invoking:\n{}\n\n{}"
            )
            diff_source = git_diff.splitlines(keepends=True)
        if diff_source:
            log_info("Parsing changes...", "")
            diffs = UnifiedFormatParser(diff_source)
            debug.debug_print_parsed_diff(diffs)
            log_info(" [OK]")
    except (DiffReportError, ReportError, UnifiedFormatParseError) as e:
        print("ERROR: {}".format(e))
        sys.exit(1)

    if args.patch or args.baseline_rev:
        log_info("Patching baseline...", "")
        baseline_patched = baseline.patch(diffs)
        debug.debug_print_patched_report(baseline_patched)
        log_info(" [OK]")
        output = new_rep - baseline_patched
    else:
        output = new_rep - baseline

    print(output, end="", file=file_out)

    if len(output) > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])
