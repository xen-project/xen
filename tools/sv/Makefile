sv_insdir := $(prefix)/var/xen/sv

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
	@mkdir -p $(sv_insdir)
	@install -m0644 Main.rpy $(sv_insdir)

	# copy XenSV images
	@mkdir -p $(sv_insdir)/images
	@(cd images && install -m0644 $(IMAGES) $(sv_insdir)/images)

	# copy XenSV stylesheet
	@mkdir -p $(sv_insdir)/inc
	@install -m0644 inc/style.css $(sv_insdir)/inc
	@install -m0644 inc/script.js $(sv_insdir)/inc

clean:

