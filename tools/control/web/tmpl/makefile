src0 = xenostyle.css
src1 = index.jsp newdom.jsp about.jsp help.jsp vd.jsp \
       vd-pv.jsp vd-pa.jsp vd-vdv.jsp vd-vdc.jsp vd-vdd.jsp vd-vdr.jsp \
       vd-fv.jsp vd-vbdv.jsp vd-vbdc.jsp vd-vbdd.jsp vd-vbdf.jsp \
       vd-par.jsp vd-vdcr.jsp vd-vddr.jsp vd-vdrr.jsp \
       vd-vbdcr.jsp vd-vbdfr.jsp \
       dom.jsp dom-lis.jsp dom-new.jsp dom-newr.jsp dom-sta.jsp dom-star.jsp \
       dom-stp.jsp dom-stpr.jsp dom-del.jsp dom-delr.jsp
target = ..
target1 = $(target)/index.jsp $(target)/newdom.jsp $(target)/vd.jsp \
          $(target)/vd-pv.jsp $(target)/vd-pa.jsp $(target)/vd-vdv.jsp \
          $(target)/vd-vdc.jsp $(target)/vd-vdd.jsp $(target)/vd-vdr.jsp \
          $(target)/vd-fv.jsp $(target)/vd-vbdv.jsp $(target)/vd-vbdc.jsp \
          $(target)/vd-vbdd.jsp $(target)/vd-vbdf.jsp \
          $(target)/about.jsp $(target)/help.jsp \
          $(target)/vd-par.jsp $(target)/vd-vdcr.jsp $(target)/vd-vddr.jsp \
          $(target)/vd-vdrr.jsp $(target)/vd-vbdcr.jsp $(target)/vd-vbdfr.jsp \
          $(target)/dom.jsp $(target)/dom-lis.jsp $(target)/dom-new.jsp \
          $(target)/dom-newr.jsp $(target)/dom-sta.jsp $(target)/dom-star.jsp \
          $(target)/dom-stp.jsp $(target)/dom-stpr.jsp \
          $(target)/dom-del.jsp $(target)/dom-delr.jsp

.SUFFIXES: .tmpl .jsp

.tmpl.jsp:
	./install.pl $*

all: $(src0) $(src1)
	./install.pl -s -home index
	mv *.jsp  $(target)
	cp $(src0) $(target)

clean:
	rm -f $(target1)
	rm -f $(target)/$(src0)
