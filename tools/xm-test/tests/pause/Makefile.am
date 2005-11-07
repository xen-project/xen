SUBDIRS =

TESTS = 01_pause_basic_pos.test 02_pause_badopt_neg.test \
	03_pause_badname_neg.test 04_pause_badid_neg.test

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

