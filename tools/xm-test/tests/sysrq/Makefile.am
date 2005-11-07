SUBDIRS =

TESTS = 01_sysrq_basic_neg.test \
	02_sysrq_sync_pos.test \
	03_sysrq_withreboot_pos.test

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

