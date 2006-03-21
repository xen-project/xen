
SUBDIRS =

TESTS = 01_vtpm-list_pos.test \
        02_vtpm-cat_pcrs.test \
        03_vtpm-susp_res.test

XFAIL_TESTS =

EXTRA_DIST = $(TESTS) $(XFAIL_TESTS)

TESTS_ENVIRONMENT=@TENV@

%.test: %.py
	cp $< $@
	chmod +x $@

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log
	rm -f *~
