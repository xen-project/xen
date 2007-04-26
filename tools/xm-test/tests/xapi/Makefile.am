SUBDIRS =

TESTS = 01_xapi-vm_basic.test \
	02_xapi-vbd_basic.test \
	03_xapi-network_pos.test

XFAIL_TESTS =

EXTRA_DIST = $(TESTS) $(XFAIL_TESTS) xapi_utils.py
TESTS_ENVIRONMENT=@TENV@

%.test: %.py
	cp $< $@
	chmod +x $@

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log
	rm -f *~
