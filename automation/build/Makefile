
# the base of where these containers will appear
REGISTRY := registry.gitlab.com/xen-project/xen

help:
	@echo "Builds containers for building Xen based on different distros"
	@echo "To build one run 'make DISTRO/VERSION'. Available containers:"
	@$(foreach file,$(sort $(subst .dockerfile,,$(wildcard */*.dockerfile))), \
		echo ${file} ; \
	)
	@echo "To push container builds, set the env var PUSH"

%: %.dockerfile ## Builds containers
	docker build -t $(REGISTRY)/$(@D):$(@F) -f $< $(<D)
	@if [ ! -z $${PUSH+x} ]; then \
		docker push $(REGISTRY)/$(@D):$(@F); \
	fi
