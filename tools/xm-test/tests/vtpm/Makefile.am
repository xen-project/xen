SUBDIRS =

TESTS = 01_vtpm-list_pos.test \
        02_vtpm-cat_pcrs.test \
        03_vtpm-susp_res.test \
        04_vtpm-loc_migr.test \
        05_vtpm-loc_migr.test \
        06_vtpm-susp_res_pcrs.test \
        07_vtpm-mig_pcrs.test \
        08_vtpm-mig_pcrs.test \
        09_vtpm-xapi.test

XFAIL_TESTS =

EXTRA_DIST = $(TESTS) $(XFAIL_TESTS) vtpm_utils.py
TESTS_ENVIRONMENT=@TENV@

%.test: %.py
	cp $< $@
	chmod +x $@

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log
	rm -f *~
