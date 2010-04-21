SUBDIRS =

TESTS = 01_cpupool_basic_pos.test \
	02_cpupool_manage_pos.test \
	03_cpupool_domain.test \
	04_cpupool_migrate.test

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

