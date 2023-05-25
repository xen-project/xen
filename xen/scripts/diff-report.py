#!/usr/bin/env python3

from __future__ import print_function
import os
import sys
from argparse import ArgumentParser
from xen_analysis.diff_tool.cppcheck_report import CppcheckReport
from xen_analysis.diff_tool.debug import Debug
from xen_analysis.diff_tool.report import ReportError


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

    args = parser.parse_args()

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
    except ReportError as e:
        print("ERROR: {}".format(e))
        sys.exit(1)

    output = new_rep - baseline
    print(output, end="", file=file_out)

    if len(output) > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])
