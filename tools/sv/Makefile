sv_insdir := $(prefix)/var/xen/sv

all:

install:


	# make parent directory
	mkdir -p $(sv_insdir)
	
	# copy Main.rpy file - references xen.sv.Main class
	cp Main.rpy $(sv_insdir)/

	# make images folder
	mkdir -p $(sv_insdir)/images
	
	# copy images
	cp images/xen.png	$(sv_insdir)/images/
	cp images/orb_01.jpg	$(sv_insdir)/images/
	cp images/orb_02.jpg	$(sv_insdir)/images/
	
	cp images/left-end-highlight.jpg	$(sv_insdir)/images/
	cp images/left-end-no-highlight.jpg	$(sv_insdir)/images/
	cp images/right-end-highlight.jpg	$(sv_insdir)/images/
	cp images/right-end-no-highlight.jpg	$(sv_insdir)/images/

	cp images/middle-highlight.jpg		$(sv_insdir)/images/
	cp images/middle-no-highlight.jpg	$(sv_insdir)/images/
	
	cp images/seperator.jpg			$(sv_insdir)/images/
	cp images/seperator-left-highlight.jpg	$(sv_insdir)/images/
	cp images/seperator-right-highlight.jpg	$(sv_insdir)/images/

	# make include folder
	mkdir -p $(sv_insdir)/inc
	
	#copy stylesheet
	cp inc/style.css $(sv_insdir)/inc/

clean:
