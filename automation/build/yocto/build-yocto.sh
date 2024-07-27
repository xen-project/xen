#!/bin/bash
#
# Yocto meta virtualization build and run script
#
# This script is building Yocto xen-image-minimal for qemu targets and run
# them using runqemu inside yocto to check that dom0 is booting properly.
# The build is using a local xen source tree so that specific patches can be
# tested.
# In order to optimize the build time, a build cache is used so that only xen
# packages and its dependencies are rebuilt (qemu and final image mainly).
#
# get command error even when piped.
set -o pipefail

# Directories
YOCTODIR="$HOME/yocto-layers"
CACHEDIR="$HOME/yocto-cache"
LOGDIR="$HOME/logs"
XENDIR="$HOME/xen"
BUILDDIR="$HOME/build"
OUTPUTDIR=`pwd`/binaries

# what yocto bsp we support
TARGET_SUPPORTED="qemuarm qemuarm64 qemux86-64"
VERBOSE="n"
TARGETLIST=""
BUILDJOBS="8"
IMAGE_FMT=""

# actions to do
do_clean="n"
do_build="y"
do_run="y"
do_localsrc="n"
do_dump="n"
do_copy="n"
build_result=0

# layers to include in the project
build_layerlist="poky/meta poky/meta-poky poky/meta-yocto-bsp \
                 meta-openembedded/meta-oe meta-openembedded/meta-python \
                 meta-openembedded/meta-networking \
                 meta-openembedded/meta-filesystems \
                 meta-virtualization"

# yocto image to build
build_image="xen-image-minimal"

function print_progress() {
    echo -n "$(date +%T) $*"
}

function run_task() {
    local task_name="$1"
    local task_target="$2"

    task_log="${task_name//project_}-${task_target}"

    mkdir -p "${LOGDIR}"
    print_progress
    echo -n "${task_name//project_} ${task_target}: "
    if [ "${VERBOSE}" = "n" ]; then
        "$@" > "${LOGDIR}/${task_log}.log" 2>&1
    else
        "$@" 2>&1 | tee "${LOGDIR}/${task_log}.log"
    fi

    if [ ${?} -ne 0 ]; then
        echo "Error"
        build_result=$((build_result+1))
        if [ "${do_dump}" = "y" ]; then
            echo
            echo "############ LOGS-START ############"
            cat "${LOGDIR}/${task_log}.log"
            echo "############  LOGS-END  ############"
            echo
        fi
        return 1
    else
        echo "OK"
        return 0
    fi
}

function project_create() {
    target="${1:?}"
    destdir="${BUILDDIR}/${target}"

    (
        # init yocto project
        source "${YOCTODIR}/poky/oe-init-build-env" "${destdir}"

        # add needed layers
        for layer in ${build_layerlist}; do
            bitbake-layers add-layer "${YOCTODIR}/${layer}" || exit 1
        done
    ) || return 1

    # Detect latest version available in Yocto and use it instead of default
    # one.
    XENVERS=$(grep -e "^XEN_REL" \
        "${YOCTODIR}"/meta-virtualization/recipes-extended/xen/xen_*.bb \
        2> /dev/null | tr -d ' ' | tr -d '?' | tr -d '"' \
        | sed -e "s/.*=//" | sort -V | tail -n 1)

    # customize project configuration
    cat <<EOF >> "${destdir}/conf/local.conf"
# Yocto BSP
MACHINE = "${target}"

# Use local cache to reuse previous builds results
SSTATE_DIR = "${CACHEDIR}/sstate-cache"
DL_DIR = "${CACHEDIR}/downloads"

# Enable xen and virtualization
DISTRO_FEATURES = " virtualization xen ipv4"

# Speed up run by not generating ssh host keys
IMAGE_INSTALL:append:pn-xen-image-minimal = " ssh-pregen-hostkeys"

# Save some disk space
INHERIT += "rm_work"

# Reduce number of jobs
BB_NUMBER_THREADS="${BUILDJOBS}"

# Use latest Xen version
PREFERRED_VERSION:pn-xen = "${XENVERS}%"
PREFERRED_VERSION:pn-xen-tools = "${XENVERS}%"

# Use autorev for now as Xen SHA used by latest yocto recipe for Xen does not
# include fixes required to build x86 on arm
SRCREV:pn-xen = "\${AUTOREV}"
SRCREV:pn-xen-tools = "\${AUTOREV}"

# Disable all QA errors as the recipe is not up to date with changes in Xen
# when we use local sources
ERROR_QA:pn-xen = "arch"
ERROR_QA:pn-xen-tools = "arch"

EOF

    if [ "${do_localsrc}" = "y" ]; then
        XENBASE=$(dirname "$(realpath -m "${XENDIR}")")
        XENSUB=$(basename "$(realpath -m "${XENDIR}")")

        cat <<EOF >> "${destdir}/conf/local.conf"
# Use local sources for xen and xen-tools
FILESEXTRAPATHS:prepend:pn-xen := "${XENBASE}:"
FILESEXTRAPATHS:prepend:pn-xen-tools := "${XENBASE}:"

SRC_URI:pn-xen = "file://${XENSUB}/;subdir=local-xen/"
SRC_URI:pn-xen-tools = "file://${XENSUB}/;subdir=local-xen/"

S:pn-xen = "\${WORKDIR}/local-xen/${XENSUB}"
S:pn-xen-tools = "\${WORKDIR}/local-xen/${XENSUB}"

SRCPV:pn-xen = "1"
SRCPV:pn-xen-tools = "1"

EOF
    fi
}

function project_build() {
    target="${1:?}"
    destdir="${BUILDDIR}/${target}"

    (
        source "${YOCTODIR}/poky/oe-init-build-env" "${destdir}"

        bitbake "${build_image}" || exit 1
        if [ $do_copy = "y" ]
        then
            if [ $target = "qemuarm" ]
            then
                mkdir -p $OUTPUTDIR
                cp $BUILDDIR/tmp/deploy/images/qemuarm/zImage $OUTPUTDIR
                cp $BUILDDIR/tmp/deploy/images/qemuarm/xen-qemuarm $OUTPUTDIR
                cp $BUILDDIR/tmp/deploy/images/qemuarm/xen-image-minimal-qemuarm.rootfs.tar.bz2 $OUTPUTDIR
            fi
        fi
    ) || return 1
}

function project_clean() {
    target="${1:?}"
    destdir="${BUILDDIR}/${target}"

    rm -rf "${destdir}"
}

function project_run() {
    target="${1:?}"
    destdir="${BUILDDIR}/${target}"
    (
        source "${YOCTODIR}/poky/oe-init-build-env" "${destdir}" > /dev/null 2>&1

        /usr/bin/expect <<EOF
set timeout 1000
spawn bash -c "runqemu serialstdio nographic slirp ${IMAGE_FMT}"

expect_after {
    -re "(.*)\r" {
        exp_continue
    }
    timeout {send_user "ERROR-Timeout!\n"; exit 1}
    eof {send_user "ERROR-EOF!\n"; exit 1}
}

# wait initial login
expect -re ".* login: "
send "root\r"
expect -re "root@.*# "

EOF
    exit $?
    ) || return 1
}

function help() {
    cat <<EOF
Usage: ${0} [TARGET1] [TARGET2]

This script is build the yocto xen-image-minimal for different qemu targets
and is running it after.
Without any target specified, all supported targets are done.

Options:
  -h, --help       Print this help
  -v, --verbose    Verbose build
  --list-target    List supported targets
  --clean          Clean existing project before starting
  --no-build       Do not build (to run an already built project)
  --no-run         Do not run
  --num-jobs=NUM   Define the number of parallel jobs in Yocto.
                   Default: ${BUILDJOBS}
  --dump-log       On error, dump the logs on the console
  --image=IMG      Yocto image or package to build
                   Default: xen-image-minimal
  --xen-dir=DIR    path to xen hypervisor source tree
                   if not provide, normal yocto version of xen is built
                   Default: ${XENDIR}
  --out-dir=DIR    directory where to create the projectss
                   Default: ${BUILDDIR}
  --log-dir=DIR    directory to store logs
                   Default: ${LOGDIR}
  --cache-dir=DIR  directory where to take and store build cache
                   Default: ${CACHEDIR}
  --layer-dir=DIR  directory containing the checkout of yocto layers
                   Default: ${YOCTODIR}
  --copy-output    Copy output binaries to binaries/
EOF
}

for OPTION in "$@"
do
    case ${OPTION} in
        -h|--help)
            help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE="y"
            ;;
        --list-targets)
            echo "${TARGET_SUPPORTED}"
            exit 0
            ;;
        --clean)
            do_clean="y"
            ;;
        --no-build)
            do_build="n"
            ;;
        --no-run)
            do_run="n"
            ;;
        --dump-log)
            do_dump="y"
            ;;
        --num-jobs=*)
            BUILDJOBS="${OPTION#*=}"
            ;;
        --image=*)
            build_image="${OPTION#*=}"
            ;;
        --xen-dir=*)
            XENDIR="${OPTION#*=}"
            if [ ! -e "${XENDIR}/xen/Makefile" ]; then
                echo "No Xen source tree in ${XENDIR}"
                exit 1
            fi
            do_localsrc="y"
            ;;
        --out-dir=*)
            BUILDDIR="${OPTION#*=}"
            ;;
        --log-dir=*)
            LOGDIR="${OPTION#*=}"
            ;;
        --cache-dir=*)
            CACHEDIR="${OPTION#*=}"
            ;;
        --layer-dir=*)
            YOCTODIR="${OPTION#*=}"
            ;;
        --copy-output)
            do_copy="y"
            ;;
        --*)
            echo "Invalid option ${OPTION}"
            help
            exit 1
            ;;
        *)
            if echo "${TARGET_SUPPORTED}" | grep -q -w "${OPTION}"; then
                TARGETLIST="${TARGETLIST} ${OPTION}"
            else
                echo "Unsupported target ${OPTION}"
                exit 1
            fi
            ;;
    esac
done

# if no target is specified build all targets
if [ -z "${TARGETLIST}" ]; then
    TARGETLIST="${TARGET_SUPPORTED}"
fi

mkdir -p "${CACHEDIR}"
mkdir -p "${LOGDIR}"
mkdir -p "${BUILDDIR}"

# Make sure we have an absolute path
YOCTODIR=$(realpath -m "${YOCTODIR}")
CACHEDIR=$(realpath -m "${CACHEDIR}")
BUILDDIR=$(realpath -m "${BUILDDIR}")
LOGDIR=$(realpath -m "${LOGDIR}")
if [ "${do_localsrc}" = "y" ]; then
    XENDIR=$(realpath -m "${XENDIR}")
fi

# Check that we have all the layers we need
for f in ${build_layerlist}; do
    if [ ! -f "${YOCTODIR}/${f}/conf/layer.conf" ]; then
        echo "Layer ${f} missing in ${YOCTODIR}"
        exit 1
    fi
done

for f in ${TARGETLIST}; do
    if [ "${do_clean}" = "y" ]; then
        run_task project_clean "${f}"
    fi
    if [ ! -f "${BUILDDIR}/${f}/conf/local.conf" ]; then
        run_task project_create "${f}"
    fi
    if [ -f "${BUILDDIR}/${f}/conf/local.conf" ]; then
        # Set the right image target
        if [ "$f" = "qemux86-64" ]; then
            IMAGE_FMT=""
        else
            IMAGE_FMT="ext4"
        fi

        if [ "${do_build}" = "y" ]; then
            run_task project_build "${f}"
        fi
        if [ "${do_run}" = "y" ]; then
            run_task project_run "${f}"
        fi

    fi
done

print_progress "Build Complete (${build_result} errors)"
echo
exit ${build_result}

