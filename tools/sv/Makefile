sv_insdir := /var/lib/xen/sv
INSTALL		= install
INSTALL_DIR	= $(INSTALL) -d -m0755
INSTALL_DATA	= $(INSTALL) -m0644

all:

IMAGES	 = xen.png orb_01.jpg orb_02.jpg
IMAGES	+= left-end-highlight.jpg left-end-no-highlight.jpg
IMAGES	+= right-end-highlight.jpg right-end-no-highlight.jpg
IMAGES	+= middle-highlight.jpg middle-no-highlight.jpg
IMAGES	+= seperator.jpg
IMAGES	+= seperator-left-highlight.jpg seperator-right-highlight.jpg
IMAGES	+= shutdown.png reboot.png pause.png unpause.png destroy.png
IMAGES	+= small-destroy.png small-pause.png small-unpause.png
IMAGES	+= next.png previous.png finish.png

install:
	# copy XenSV Main.rpy file
	@[ -d $(DESTDIR)$(sv_insdir) ] || $(INSTALL_DIR) $(DESTDIR)$(sv_insdir)
	@$(INSTALL_DATA) Main.rpy $(DESTDIR)$(sv_insdir)

	# copy XenSV images
	@[ -d $(DESTDIR)$(sv_insdir)/images ] || \
		$(INSTALL_DIR) $(DESTDIR)$(sv_insdir)/images
	@(cd images && $(INSTALL_DATA) $(IMAGES) $(DESTDIR)$(sv_insdir)/images)

	# copy XenSV stylesheet
	@[ -d $(DESTDIR)$(sv_insdir)/inc ] || \
		$(INSTALL_DIR) $(DESTDIR)$(sv_insdir)/inc
	@$(INSTALL_DATA) inc/style.css inc/script.js $(DESTDIR)$(sv_insdir)/inc

clean:

