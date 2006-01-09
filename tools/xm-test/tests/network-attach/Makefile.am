
SUBDIRS =

TESTS = 01_network_attach_pos.test \
	02_network_attach_detach_pos.test \
	03_network_attach_detach_multiple_pos.test  \
	04_network_attach_baddomain_neg.test

XFAIL_TESTS = 

EXTRA_DIST = $(TESTS) $(XFAIL_TESTS) network_utils.py

TESTS_ENVIRONMENT=@TENV@

%.test: %.py
	cp $< $@
	chmod +x $@

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log
	rm -f *~
