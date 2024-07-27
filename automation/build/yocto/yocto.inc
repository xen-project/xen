# This makefile generates the docker files for Yocto builds.
# The containers for the current architecture are the one built using make all.
# To build containers for a different architecture, you need to call make for
# the image you want explicitely.
# The containers are named this way:
# YOCTOVERSION-TARGET for x86_64 hosts
# YOCTOVERSION-TARGET-arm64v8 for arm64 hosts
# For example you can build an arm64 container with the following command:
# make yocto/scarthgap-qemuarm64-arm64v8

# Yocto versions we are currently using.
YOCTO_VERSION = scarthgap

# Yocto BSPs we want to build for.
YOCTO_TARGETS = qemuarm64 qemuarm qemux86-64

# Supported container architectures.
YOCTO_ARCHS = amd64 arm64v8

# Architecture we want to use in gitlab CI (depends on runners arch).
CI_ARCH-qemuarm64 = arm64v8
CI_ARCH-qemuarm = arm64v8
CI_ARCH-qemux86-64 = amd64

define GEN_DOCKER
# Make all is generating architecture we use in the CI.
ifeq ($(CI_ARCH-$(2)),$(3))
CONTAINERS += yocto/$(1)-$(2)$(4)
else
CONTAINERS_EXTRA += yocto/$(1)-$(2)$(4)
endif

.INTERMEDIATE: yocto/$(1)-$(2)$(4).dockerfile

yocto/$(1)-$(2)$(4).dockerfile: yocto/yocto.dockerfile.in
	@cat $$< | \
	    sed -e "s,##YOCTOVERSION##,$(1),g" | \
	    sed -e "s,##YOCTOTARGET##,$(2),g" | \
	    sed -e "s,##DOCKERPLAT##,$(3)/,g" > $$@

endef

$(eval $(foreach version,$(YOCTO_VERSION),\
       $(foreach target,$(YOCTO_TARGETS),\
       $(foreach arch,$(YOCTO_ARCHS),\
       $(call GEN_DOCKER,$(version),$(target),$(arch),$(if $(filter amd64,$(arch)),,-$(arch)))))))
