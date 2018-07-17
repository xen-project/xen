FROM registry.gitlab.com/xen-project/xen/suse:sles11sp4-base
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV USER root

RUN mkdir /build
WORKDIR /build

# Nothing else is needed -- base image already contain everything.

# Note:
#
# SLES11 SP4 runs pre-2.13 glibc, which requires vsyscall support.  Most
# distros nowadays disable vsyscall. To run this container, the host needs to
# have vsyscall=emulate in its kernel command line.
#
# Due to various issues in SLES11 SP4, you might want to disable building
# certain components. Known *not bulding* components include OVMF, SEABIOS
# and upstream QEMU.
