src0 = xenostyle.css
src1 = index.jsp about.jsp help.jsp vd.jsp \
       vd-pv.jsp vd-pa.jsp vd-vdv.jsp vd-vdc.jsp vd-vdd.jsp vd-vdr.jsp \
       vd-fv.jsp vd-vbdv.jsp vd-vbdc.jsp vd-vbdd.jsp vd-vbdf.jsp \
       vd-par.jsp vd-vdcr.jsp vd-vddr.jsp vd-vdrr.jsp \
       vd-vbdcr.jsp vd-vbdfr.jsp \
       dom.jsp dom-lis.jsp dom-new.jsp dom-newr.jsp dom-sta.jsp dom-star.jsp \
       dom-stp.jsp dom-stpr.jsp dom-del.jsp dom-delr.jsp \
       pd.jsp pd-g.jsp pd-gr.jsp pd-l.jsp pd-r.jsp pd-rr.jsp
target = ..
target0 = $(target)/xenostyle.css
target1 = $(target)/index.jsp $(target)/vd.jsp \
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
          $(target)/dom-del.jsp $(target)/dom-delr.jsp \
          $(target)/pd.jsp $(target)/pd-g.jsp $(target)/pd-gr.jsp \
          $(target)/pd-l.jsp $(target)/pd-r.jsp $(target)/pd-rr.jsp

.SUFFIXES: .tmpl .jsp

all: $(target1) $(target0)

$(target)/index.jsp: index.tmpl
	./install.pl -s -home index
	mv index.jsp $(target)

$(target)/%.jsp: %.tmpl xenofoot.def xenohead.def
	./install.pl $*
	mv $*.jsp $(target)
	
$(target0): $(src0)
	cp -f $(src0) $(target)

clean:
	rm -f $(target1) $(target0)
