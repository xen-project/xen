SUBDIRS =

TESTS = 01_restore_basic_pos.test \
	02_restore_badparm_neg.test \
	03_restore_badfilename_neg.test \
	04_restore_withdevices_pos.test

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

