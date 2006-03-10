
SUBDIRS =

TESTS = 01_sedf_period_slice_pos.py 02_sedf_period_lower_neg.py \
        03_sedf_slice_lower_neg.py  04_sedf_slice_upper_neg.py  \
        05_sedf_extratime_pos.py 06_sedf_extratime_disable_neg.py

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
