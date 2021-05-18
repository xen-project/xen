
# the base of where these containers will appear
REGISTRY := registry.gitlab.com/xen-project/xen
CONTAINERS = $(subst .dockerfile,,$(wildcard */*.dockerfile))
DOCKER_CMD ?= docker

help:
	@echo "Builds containers for building Xen based on different distros"
	@echo "To build one run 'make DISTRO/VERSION'. Available containers:"
	@$(foreach file,$(sort $(CONTAINERS)),echo ${file};)
	@echo "To push container builds, set the env var PUSH"

%: %.dockerfile ## Builds containers
	$(DOCKER_CMD) build -t $(REGISTRY)/$(@D):$(@F) -f $< $(<D)
	@if [ ! -z $${PUSH+x} ]; then \
		$(DOCKER_CMD) push $(REGISTRY)/$(@D):$(@F); \
	fi

.PHONY: all
all: $(CONTAINERS)
