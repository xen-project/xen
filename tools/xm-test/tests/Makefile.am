SUBDIRS = 	               	\
		block-create	\
	  	block-list	\
                block-destroy   \
		console		\
		create 		\
		destroy		\
		dmesg		\
		domid		\
		domname		\
	 	help		\
		info		\
		list		\
		memmax		\
		memset		\
		network-attach	\
		pause		\
		reboot 		\
		sedf		\
		shutdown	\
		sysrq		\
		unpause         \
		vcpu-disable    \
		vcpu-pin	\
		enforce_dom0_cpus	\
		save restore migrate

DISABLED_TESTS = save	\
	        restore \
	        migrate

TESTS =

XFAIL_TESTS = 

EXTRA_DIST = $(TESTS) $(XFAIL_TESTS) $(SUBDIRS) $(DISABLED_TESTS) Makefile.am.template

%.test: %.py
	cp $< $@
	chmod +x $@

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log

