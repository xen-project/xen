SUBDIRS =

TESTS = 01_destroy_basic_pos.test \
	02_destroy_noparm_neg.test \
	03_destroy_nonexist_neg.test \
	04_destroy_badparm_neg.test \
	05_destroy_byid_pos.test  \
	06_destroy_dom0_neg.test \
	07_destroy_stale_pos.test

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

