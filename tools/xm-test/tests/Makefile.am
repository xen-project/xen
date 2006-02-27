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
		network		\
		network-attach	\
		pause		\
		reboot 		\
		sedf		\
		shutdown	\
		sysrq		\
		unpause         \
		vcpu-disable    \
		vcpu-pin	\
		vtpm            \
		enforce_dom0_cpus	\
		save restore migrate

EXTRA_DIST = $(SUBDIRS) Makefile.am.template

%.test: %.py
	cp $< $@
	chmod +x $@

clean-local: am_config_clean-local

am_config_clean-local:
	rm -f *test
	rm -f *log

