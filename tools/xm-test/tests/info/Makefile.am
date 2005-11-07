
SUBDIRS =

TESTS = 01_info_basic_pos.test \
	02_info_compiledata_pos.test

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
