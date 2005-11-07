
SUBDIRS =

TESTS = 01_console_badopt_neg.test \
	02_console_baddom_neg.test

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
