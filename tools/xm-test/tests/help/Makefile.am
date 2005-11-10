SUBDIRS =

TESTS = 01_help_basic_pos.test \
	02_help_basic_neg.test \
	03_help_badparm_neg.test \
	04_help_long_pos.test \
	05_help_nonroot_pos.test \
	06_help_allcmds.test

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

