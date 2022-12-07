#!/usr/bin/env python3

import sys
from xen_analysis import settings, generic_analysis
from xen_analysis.generic_analysis import *


def main(argv):
    ret_code = 0
    settings.parse_commandline(argv)
    try:
        if settings.step_parse_tags:
            generic_analysis.parse_xen_tags()
        if settings.step_build_xen:
            generic_analysis.build_xen()
    except (ParseTagPhaseError, BuildPhaseError) as e:
        print("ERROR: {}".format(e))
        if hasattr(e, "errorcode"):
            ret_code = e.errorcode
    finally:
        if settings.step_clean_analysis:
            e = generic_analysis.clean_analysis_artifacts()
            if e:
                print("ERROR: {}".format(e))
                ret_code = 1

    sys.exit(ret_code)


if __name__ == "__main__":
    main(sys.argv[1:])
