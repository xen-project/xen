
# the base of where these containers will appear
REGISTRY := registry.gitlab.com/xen-project/xen
CONTAINERS := $(filter-out yocto/%,$(subst .dockerfile,,$(wildcard */*.dockerfile)))
CONTAINERS_EXTRA =
DOCKER_CMD ?= docker

help:
	@echo "Builds containers for building Xen based on different distros"
	@echo "To build one run 'make DISTRO/VERSION'. Available containers:"
	@$(foreach file,$(sort $(CONTAINERS)),echo $(file);)
	@echo "Extra containers (not built using make all):"
	@$(foreach file,$(sort $(CONTAINERS_EXTRA)),echo $(file);)
	@echo "To push container builds, set the env var PUSH"

include yocto/yocto.inc

%: %.dockerfile ## Builds containers
	$(DOCKER_CMD) build --pull -t $(REGISTRY)/$(@D):$(@F) -f $< $(<D)
	@if [ ! -z $${PUSH+x} ]; then \
		$(DOCKER_CMD) push $(REGISTRY)/$(@D):$(@F); \
	fi

.PHONY: all clean
all: $(CONTAINERS)

# Remove generated dockerfiles for yocto
clean:
	rm -f yocto/*.dockerfile

define CLEAN_RULE
.PHONY: clean-$(1)
clean-$(1):
	if [ -n "$$$$(docker image ls -q $(REGISTRY)/$(subst /,:,$(1)))" ]; then \
		docker image rm $(REGISTRY)/$(subst /,:,$(1)); \
	fi

endef

$(eval $(foreach img,$(CONTAINERS) $(CONTAINERS_EXTRA),$(call CLEAN_RULE,$(img))))
