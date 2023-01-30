#!/usr/bin/env python3

import sys, re, os

module_dir = os.path.dirname(os.path.realpath(__file__))
xen_dir = os.path.realpath(module_dir + "/../..")
repo_dir = os.path.realpath(xen_dir + "/..")
tools_dir = os.path.realpath(xen_dir + "/tools")

step_get_make_vars = False
step_parse_tags = True
step_cppcheck_deps = False
step_build_xen = True
step_cppcheck_report = False
step_clean_analysis = True
step_distclean_analysis = False

target_build = False
target_clean = False
target_distclean = False

analysis_tool = ""
cppcheck_binpath = "cppcheck"
cppcheck_html = False
cppcheck_htmlreport_binpath = "cppcheck-htmlreport"
cppcheck_misra = False
cppcheck_skip_rules = ""
make_forward_args = ""
outdir = xen_dir


def help():
    msg="""
Usage: {} [OPTION] ... [-- [make arguments]]

This script runs the analysis on the Xen codebase.

The phases for the analysis are <tags>, <build>, <clean>, <cppcheck report>

Depending on the options below, only some phases will run:

<no options>: tags, build, [cppcheck report], clean
--build-only: build, [cppcheck report]
--clean-only: clean
--distclean:  clean, [destroy cppcheck report]
--no-build:   tags, clean
--no-clean:   tags, build

--no-build/--no-clean can be passed together to avoid both clean and build
phases.
Tags and build phases need to specify --run-coverity, --run-eclair or
--run-cppcheck.
Cppcheck report creation phase runs only when --run-cppcheck is passed to the
script.

Options:
  --build-only            Run only the commands to build Xen with the optional
                          make arguments passed to the script
  --clean-only            Run only the commands to clean the analysis artifacts
  --cppcheck-bin=         Path to the cppcheck binary (Default: {})
  --cppcheck-html         Produce an additional HTML output report for Cppcheck
  --cppcheck-html-bin=    Path to the cppcheck-html binary (Default: {})
  --cppcheck-misra        Activate the Cppcheck MISRA analysis
  --cppcheck-skip-rules=  List of MISRA rules to be skipped, comma separated.
                          (e.g. --cppcheck-skip-rules=1.1,20.7,8.4)
  --distclean             Clean analysis artifacts and reports
  -h, --help              Print this help
  --no-build              Skip the build Xen phase
  --no-clean              Don\'t clean the analysis artifacts on exit
  --run-coverity          Run the analysis for the Coverity tool
  --run-cppcheck          Run the Cppcheck analysis tool on Xen
  --run-eclair            Run the analysis for the Eclair tool
"""
    print(msg.format(sys.argv[0], cppcheck_binpath,
                     cppcheck_htmlreport_binpath))


def parse_commandline(argv):
    global analysis_tool
    global cppcheck_binpath
    global cppcheck_html
    global cppcheck_htmlreport_binpath
    global cppcheck_misra
    global cppcheck_skip_rules
    global make_forward_args
    global outdir
    global step_get_make_vars
    global step_parse_tags
    global step_cppcheck_deps
    global step_build_xen
    global step_cppcheck_report
    global step_clean_analysis
    global step_distclean_analysis
    global target_build
    global target_clean
    global target_distclean
    forward_to_make = False
    for option in argv:
        args_with_content_regex = re.match(r'^(--[a-z]+[a-z-]*)=(.*)$', option)

        if forward_to_make:
            # Intercept outdir
            outdir_regex = re.match("^O=(.*)$", option)
            if outdir_regex:
                outdir = outdir_regex.group(1)
            # Forward any make arguments
            make_forward_args = make_forward_args + " " + option
        elif option == "--build-only":
            target_build = True
        elif option == "--clean-only":
            target_clean = True
        elif args_with_content_regex and \
             args_with_content_regex.group(1) == "--cppcheck-bin":
            cppcheck_binpath = args_with_content_regex.group(2)
        elif option == "--cppcheck-html":
            cppcheck_html = True
        elif args_with_content_regex and \
             args_with_content_regex.group(1) == "--cppcheck-html-bin":
            cppcheck_htmlreport_binpath = args_with_content_regex.group(2)
        elif option == "--cppcheck-misra":
            cppcheck_misra = True
        elif args_with_content_regex and \
             args_with_content_regex.group(1) == "--cppcheck-skip-rules":
            cppcheck_skip_rules = args_with_content_regex.group(2)
        elif option == "--distclean":
            target_distclean = True
        elif (option == "--help") or (option == "-h"):
            help()
            sys.exit(0)
        elif option == "--no-build":
            step_build_xen = False
        elif option == "--no-clean":
            step_clean_analysis = False
        elif (option == "--run-coverity") or (option == "--run-eclair"):
            analysis_tool = option[6:]
        elif (option == "--run-cppcheck"):
            analysis_tool = "cppcheck"
            step_get_make_vars = True
            step_cppcheck_deps = True
            step_cppcheck_report = True
        elif option == "--":
            forward_to_make = True
        else:
            print("Invalid option: {}".format(option))
            help()
            sys.exit(1)

    if target_build and (target_clean or target_distclean):
        print("--build-only is not compatible with --clean-only/--distclean "
              "argument.")
        sys.exit(1)

    if target_distclean:
        # Implicit activation of clean target
        target_clean = True

        step_distclean_analysis = True

    if target_clean:
        step_get_make_vars = False
        step_parse_tags = False
        step_cppcheck_deps = False
        step_build_xen = False
        step_cppcheck_report = False
        step_clean_analysis = True
        return

    if analysis_tool == "":
        print("Please specify one analysis tool.")
        help()
        sys.exit(1)

    if target_build:
        step_parse_tags = False
        step_build_xen = True
        step_clean_analysis = False
