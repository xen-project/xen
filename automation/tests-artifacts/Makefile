
# the base of where these containers will appear
REGISTRY := registry.gitlab.com/xen-project/xen/tests-artifacts
CONTAINERS = $(subst .dockerfile,,$(wildcard */*.dockerfile))

help:
	@echo "Containers to build and export tests artifacts."
	@echo "To build one run 'make ARTIFACT/VERSION'. Available containers:"
	@$(foreach file,$(sort $(CONTAINERS)),echo ${file};)
	@echo "To push container builds, set the env var PUSH"

%: %.dockerfile ## Builds containers
	$(DOCKER_CMD) build --pull -t $(REGISTRY)/$(@D):$(@F) -f $< $(<D)
	@if [ ! -z $${PUSH+x} ]; then \
		$(DOCKER_CMD) push $(REGISTRY)/$(@D):$(@F); \
	fi

.PHONY: all
all: $(CONTAINERS)
