SUBDIRS =

TESTS = 01_security-acm_basic.test \
        02_security-acm_dom_start.test \
        03_security-acm_dom_conflict.test \
        04_security-acm_dom_res.test \
        05_security-acm_dom_res_conf.test \
        06_security-acm_dom_block_attach.test \
        07_security-acm_pol_update.test \
        08_security-acm_xapi.test \
        09_security-acm_pol_update.test \
        10_security-acm_pol_update.test

XFAIL_TESTS =

EXTRA_DIST = $(TESTS) $(XFAIL_TESTS) acm_utils.py
TESTS_ENVIRONMENT=@TENV@

%.test: %.py
	cp $< $@
	chmod +x $@
	@if [ -d /etc/xen/acm-security/policies ]; then \
		cp -f xm-test-security_policy.xml       \
		      xm-test-update-security_policy.xml\
		      /etc/xen/acm-security/policies;   \
	fi;

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log
	rm -f *~
