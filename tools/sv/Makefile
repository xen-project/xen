sv_insdir := $(prefix)/var/xen/sv

all:

install:
	# make parent directory
	mkdir -p $(sv_insdir)
	
	# copy Main.rpy file - references xen.sv.Main class
	install -m0644 Main.rpy $(sv_insdir)

	# make images folder
	mkdir -p $(sv_insdir)/images
	
	# copy images
	install -m0644 images/xen.png $(sv_insdir)/images
	install -m0644 images/orb_01.jpg $(sv_insdir)/images
	install -m0644 images/orb_02.jpg $(sv_insdir)/images
	
	install -m0644 images/left-end-highlight.jpg $(sv_insdir)/images
	install -m0644 images/left-end-no-highlight.jpg $(sv_insdir)/images
	install -m0644 images/right-end-highlight.jpg $(sv_insdir)/images
	install -m0644 images/right-end-no-highlight.jpg $(sv_insdir)/images

	install -m0644 images/middle-highlight.jpg $(sv_insdir)/images
	install -m0644 images/middle-no-highlight.jpg $(sv_insdir)/images
	
	install -m0644 images/seperator.jpg $(sv_insdir)/images
	install -m0644 images/seperator-left-highlight.jpg $(sv_insdir)/images
	install -m0644 images/seperator-right-highlight.jpg $(sv_insdir)/images
	
	install -m0644 images/shutdown.png $(sv_insdir)/images
	install -m0644 images/reboot.png $(sv_insdir)/images
	install -m0644 images/pause.png $(sv_insdir)/images
	install -m0644 images/unpause.png $(sv_insdir)/images
        
	install -m0644 images/next.png $(sv_insdir)/images
	install -m0644 images/previous.png $(sv_insdir)/images        
	install -m0644 images/finish.png $(sv_insdir)/images 
        
	# make include folder
	mkdir -p $(sv_insdir)/inc
	
	# copy stylesheet
	install -m0644 inc/style.css $(sv_insdir)/inc
	install -m0644 inc/script.js $(sv_insdir)/inc

clean:

