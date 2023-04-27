#!/usr/bin/env python3

import sys
from xen_analysis import settings, generic_analysis, cppcheck_analysis
from xen_analysis.generic_analysis import *
from xen_analysis.cppcheck_analysis import *

PhaseExceptions = (GetMakeVarsPhaseError, ParseTagPhaseError,
                   CppcheckDepsPhaseError, BuildPhaseError,
                   CppcheckReportPhaseError)


def main(argv):
    ret_code = 0
    settings.parse_commandline(argv)
    try:
        if settings.step_get_make_vars:
            cppcheck_analysis.get_make_vars()
        if settings.step_parse_tags:
            generic_analysis.parse_xen_tags()
        if settings.step_cppcheck_deps:
            cppcheck_analysis.generate_cppcheck_deps()
        if settings.step_build_xen:
            generic_analysis.build_xen()
        if settings.step_cppcheck_report:
            cppcheck_analysis.generate_cppcheck_report()
    except PhaseExceptions as e:
        print("ERROR: {}".format(e))
        ret_code = getattr(e, "errorcode", 1)
    finally:
        if settings.step_clean_analysis:
            cppcheck_analysis.clean_analysis_artifacts()
            e = generic_analysis.clean_analysis_artifacts()
            if e:
                print("ERROR: {}".format(e))
                ret_code = 1
        if settings.step_distclean_analysis:
            cppcheck_analysis.clean_reports()

    sys.exit(ret_code)


if __name__ == "__main__":
    main(sys.argv[1:])
