#!/usr/bin/env python3

import sys, re, os

module_dir = os.path.dirname(os.path.realpath(__file__))
xen_dir = os.path.realpath(module_dir + "/../..")
repo_dir = os.path.realpath(xen_dir + "/..")
tools_dir = os.path.realpath(xen_dir + "/tools")

step_parse_tags = True
step_build_xen = True
step_clean_analysis = True

target_build = False
target_clean = False

analysis_tool = ""
make_forward_args = ""
outdir = xen_dir


def help():
    msg="""
Usage: {} [OPTION] ... [-- [make arguments]]

This script runs the analysis on the Xen codebase.

The phases for the analysis are <tags>, <build>, <clean>

Depending on the options below, only some phases will run:

<no options>: tags, build, clean
--build-only: build
--clean-only: clean
--no-build:   tags, clean
--no-clean:   tags, build

--no-build/--no-clean can be passed together to avoid both clean and build
phases.
Tags and build phases need to specify --run-coverity or --run-eclair.

Options:
  --build-only    Run only the commands to build Xen with the optional make
                  arguments passed to the script
  --clean-only    Run only the commands to clean the analysis artifacts
  -h, --help      Print this help
  --no-build      Skip the build Xen phase
  --no-clean      Don\'t clean the analysis artifacts on exit
  --run-coverity  Run the analysis for the Coverity tool
  --run-eclair    Run the analysis for the Eclair tool
"""
    print(msg.format(sys.argv[0]))


def parse_commandline(argv):
    global analysis_tool
    global make_forward_args
    global outdir
    global step_parse_tags
    global step_build_xen
    global step_clean_analysis
    global target_build
    global target_clean
    forward_to_make = False
    for option in argv:
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
        elif (option == "--help") or (option == "-h"):
            help()
            sys.exit(0)
        elif option == "--no-build":
            step_build_xen = False
        elif option == "--no-clean":
            step_clean_analysis = False
        elif (option == "--run-coverity") or (option == "--run-eclair"):
            analysis_tool = option[6:]
        elif option == "--":
            forward_to_make = True
        else:
            print("Invalid option: {}".format(option))
            help()
            sys.exit(1)

    if target_build and target_clean:
        print("--build-only is not compatible with --clean-only argument.")
        sys.exit(1)

    if target_clean:
        step_parse_tags = False
        step_build_xen = False
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
