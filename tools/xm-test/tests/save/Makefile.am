SUBDIRS =

TESTS = 01_save_basic_pos.test \
	02_save_badparm_neg.test \
	03_save_bogusfile_neg.test


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

