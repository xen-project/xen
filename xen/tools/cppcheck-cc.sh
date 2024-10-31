#!/usr/bin/env bash

set -e

function help() {
    cat <<EOF
Usage: ${0} [OPTION] ... -- <compiler arguments>

This script is a wrapper for cppcheck that enables it to analyse the files that
are the target for the build, it is used in place of a selected compiler and the
make process will run it on every file that needs to be built.
All the arguments passed to the original compiler are forwarded to it without
modification, furthermore, they are used to improve the cppcheck analysis.

Options:
  --compiler=       Use this compiler for the build
  --cppcheck-cmd=   Command line for the cppcheck analysis.
  --cppcheck-html   Prepare for cppcheck HTML output
  --cppcheck-plat=  Path to the cppcheck platform folder
  --ignore-path=    This script won't run cppcheck on the files having this
                    path, the compiler will run anyway on them. This argument
                    can be specified multiple times.
  -h, --help        Print this help
EOF
}

BUILD_DIR=""
CC_FILE=""
OBJ_FILE=""
COMPILER=""
CPPCHECK_HTML="n"
CPPCHECK_PLAT_PATH=""
CPPCHECK_TOOL=""
CPPCHECK_TOOL_ARGS=""
FORWARD_FLAGS=""
IGNORE_PATH="n"
IGNORE_PATH_LIST=""
JDB_FILE=""
OBJTREE_PATH=""

# Variable used for arg parsing
forward_to_cc="n"
sm_tool_args="n"
obj_arg_content="n"

for OPTION in "$@"
do
    if [ "${forward_to_cc}" = "y" ]; then
        if [[ ${OPTION} == *.c ]]
        then
            CC_FILE="${OPTION}"
        elif [ "${OPTION}" = "-o" ]
        then
            # After -o there is the path to the obj file, flag it
            obj_arg_content="y"
        elif [ "${obj_arg_content}" = "y" ]
        then
            # This must be the path to the obj file, turn off flag and save path
            OBJTREE_PATH="$(dirname "${OPTION}")"
            OBJ_FILE="$(basename "${OPTION}")"
            obj_arg_content="n"
        fi
        # Forward any argument to the compiler
        FORWARD_FLAGS="${FORWARD_FLAGS} ${OPTION}"
        continue
    fi
    case ${OPTION} in
        -h|--help)
            help
            exit 0
            ;;
        --build-dir=*)
            BUILD_DIR="${OPTION#*=}"
            sm_tool_args="n"
            ;;
        --compiler=*)
            COMPILER="${OPTION#*=}"
            sm_tool_args="n"
            ;;
        --cppcheck-cmd=*)
            CPPCHECK_TOOL="${OPTION#*=}"
            sm_tool_args="y"
            ;;
        --cppcheck-html)
            CPPCHECK_HTML="y"
            sm_tool_args="n"
            ;;
        --cppcheck-plat=*)
            CPPCHECK_PLAT_PATH="${OPTION#*=}"
            sm_tool_args="n"
            ;;
        --ignore-path=*)
            IGNORE_PATH_LIST="${IGNORE_PATH_LIST} ${OPTION#*=}"
            sm_tool_args="n"
            ;;
        --)
            forward_to_cc="y"
            sm_tool_args="n"
            ;;
        *)
            if [ "${sm_tool_args}" = "y" ]; then
                CPPCHECK_TOOL_ARGS="${CPPCHECK_TOOL_ARGS} ${OPTION}"
            else
                echo "Invalid option ${OPTION}"
                exit 1
            fi
            ;;
    esac
done

if [ "${COMPILER}" = "" ]
then
    echo "--compiler arg is mandatory."
    exit 1
fi

if [ "${BUILD_DIR}" = "" ]
then
    echo "--build-dir arg is mandatory."
    exit 1
fi

function create_jcd() {
    local line="${1}"
    local arg_num=0
    local same_line=0

    {
        echo "["
        echo "    {"
        echo "        \"arguments\": ["

        for arg in ${line}; do
            # This code prevents to put comma in the last element of the list or
            # on sequential lines that are going to be merged
            if [ "${arg_num}" -ne 0 ] && [ "${same_line}" -eq 0 ]
            then
                echo ","
            fi
            if [ "${same_line}" -ne 0 ]
            then
                echo -n "${arg}\""
                same_line=0
            elif [ "${arg}" = "-iquote" ] || [ "${arg}" = "-I" ]
            then
                # cppcheck doesn't understand -iquote, substitute with -I
                echo -n "            \"-I"
                same_line=1
            else
                echo -n "            \"${arg}\""
            fi
            arg_num=$(( arg_num + 1 ))
        done
        echo ""
        echo "        ],"
        echo "        \"directory\": \"$(pwd -P)\","
        echo "        \"file\": \"${CC_FILE}\""
        echo "    }"
        echo "]"
    } > "${JDB_FILE}"
}


# Execute compiler with forwarded flags
# Shellcheck complains about missing quotes on FORWARD_FLAGS, but they can't be
# used here
# shellcheck disable=SC2086
${COMPILER} ${FORWARD_FLAGS}

if [ -n "${CC_FILE}" ];
then
    for path in ${IGNORE_PATH_LIST}
    do
        if [[ ${CC_FILE} == *${path}* ]]
        then
            IGNORE_PATH="y"
            echo "${0}: ${CC_FILE} ignored by --ignore-path matching *${path}*"
        fi
    done
    if [ "${IGNORE_PATH}" = "n" ]
    then
        JDB_FILE="${OBJTREE_PATH}/${OBJ_FILE}.json"

        # Prepare the Json Compilation Database for the file
        create_jcd "${COMPILER} ${FORWARD_FLAGS}"

        out_file="${OBJTREE_PATH}/${OBJ_FILE}.cppcheck.txt"

        # Select the right target platform, ARCH is generated from Xen Makefile
        case ${ARCH} in
            arm64)
                # arm64 has efi code compiled with -fshort-wchar
                platform="${CPPCHECK_PLAT_PATH}/arm64-wchar_t2.xml"
                ;;
            arm32)
                # arm32 has no efi code
                platform="${CPPCHECK_PLAT_PATH}/arm32-wchar_t4.xml"
                ;;
            x86_64)
                # x86_64 has efi code compiled with -fshort-wchar
                platform="${CPPCHECK_PLAT_PATH}/x86_64-wchar_t2.xml"
                ;;
            *)
                echo "ARCH: ${ARCH} not expected!"
                exit 1
                ;;
        esac

        if [ ! -f "${platform}" ]
        then
            echo "${platform} not found!"
            exit 1
        fi

        # Generate build directory for the analysed file
        cppcheck_build_dir="${BUILD_DIR}/${OBJTREE_PATH}/${OBJ_FILE}"
        mkdir -p "${cppcheck_build_dir}"

        # Shellcheck complains about missing quotes on CPPCHECK_TOOL_ARGS, but
        # they can't be used here
        # shellcheck disable=SC2086
        ${CPPCHECK_TOOL} ${CPPCHECK_TOOL_ARGS} \
            --project="${JDB_FILE}" \
            --output-file="${out_file}" \
            --platform="${platform}" \
            --cppcheck-build-dir=${cppcheck_build_dir}

        if [ "${CPPCHECK_HTML}" = "y" ]
        then
            # Shellcheck complains about missing quotes on CPPCHECK_TOOL_ARGS,
            # but they can't be used here
            # shellcheck disable=SC2086
            ${CPPCHECK_TOOL} ${CPPCHECK_TOOL_ARGS} \
                --project="${JDB_FILE}" \
                --output-file="${out_file%.txt}.xml" \
                --platform="${platform}" \
                --cppcheck-build-dir=${cppcheck_build_dir} \
                -q \
                --xml
        fi
    fi
fi
