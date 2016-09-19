.PHONY: tests
tests:
ifneq $(XEN_TARGET_ARCH),arm32)
	$(MAKE) -f $(BASEDIR)/Rules.mk -C livepatch livepatch
endif

.PHONY: clean
clean::
	$(MAKE) -f $(BASEDIR)/Rules.mk -C livepatch clean
