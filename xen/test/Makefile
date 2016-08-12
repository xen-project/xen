.PHONY: tests
tests:
ifeq ($(XEN_TARGET_ARCH),x86_64)
	$(MAKE) -f $(BASEDIR)/Rules.mk -C livepatch livepatch
endif

.PHONY: clean
clean::
	$(MAKE) -f $(BASEDIR)/Rules.mk -C livepatch clean
