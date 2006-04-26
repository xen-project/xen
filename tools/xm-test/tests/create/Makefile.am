SUBDIRS =

TESTS = 01_create_basic_pos.test \
	02_create_noparm_neg.test \
	03_create_badparm_neg.test \
	04_create_conflictname_neg.test \
	06_create_mem_neg.test \
	07_create_mem64_pos.test \
	08_create_mem128_pos.test \
	09_create_mem256_pos.test \
	10_create_fastdestroy.test \
	11_create_concurrent_pos.test \
	12_create_concurrent_stress_pos.test \
	13_create_multinic_pos.test \
	14_create_blockroot_pos.test \
	15_create_smallmem_pos.test \
	16_create_smallmem_neg.test

EXTRA_DIST = $(TESTS)

TESTS_ENVIRONMENT=@TENV@

%.test: %.py
	cp $< $@
	chmod +x $@

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log
	rm -f *~

