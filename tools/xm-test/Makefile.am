SUBDIRS = ramdisk tests
EXTRA_DIST = lib runtest.sh mkreport

existing:
	$(MAKE) -C ramdisk existing

# Remove any pyc's, CVS dirs, and prune the skel dirs
dist-hook:
	find $(distdir) -name '*~' -delete -print
	find $(distdir) -name '*.pyc' -delete -print
	for i in Root Repository Entries; do \
	  find $(distdir) -name $$i -delete ;\
	done
	find $(distdir) -name CVS -delete
	find $(distdir) -name '*.test' -delete
	cd $(distdir)/ramdisk/skel && find . -empty -delete
	chmod a+x $(distdir)/runtest.sh

