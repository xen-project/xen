#!/usr/bin/perl5
if($#ARGV<0) {
    &usage();
} else {

    $headerfile = "xenohead.def" ;
    $footerfile = "xenofoot.def" ;

    $sectionbreak = "-" ;
    $supress_section = 0 ;
    $homepage = 0 ;
    $navigationwidth = 106;
    $navigationstring = "<td><a href=\"index.jsp\"><img src=\"img/home.gif\" width=\"53\" height=\"18\" border=\"0\" alt=\"XenoServers Home Page\" class=\"block\" /></a></td>";
    $whitespace = "<tr><td><img src=\"img/pixel.gif\" class=\"block\" width=\"1\" height=\"10\"></td></tr>";
    $greyline1 = "<tr><td bgcolor=\"#cccccc\"><img src=\"img/pixel.gif\" class=\"block\" width=\"1\" height=\"2\"></td></tr>";
    $greyline2 = "<tr><td bgcolor=\"#cccccc\" colspan=\"2\"><img src=\"img/pixel.gif\" class=\"block\" width=\"1\" height=\"2\"></td></tr>";
    $greyline3 = "<tr><td bgcolor=\"#cccccc\" colspan=\"3\"><img src=\"img/pixel.gif\" class=\"block\" width=\"1\" height=\"2\"></td></tr>";
    $greyline4 = "<tr><td bgcolor=\"#cccccc\" colspan=\"4\"><img src=\"img/pixel.gif\" class=\"block\" width=\"1\" height=\"2\"></td></tr>";
    $greyline14 = "<tr><td></td><td bgcolor=\"#cccccc\" colspan=\"4\"><img src=\"img/pixel.gif\" class=\"block\" width=\"1\" height=\"2\"></td></tr>";


    $login = getlogin || (getpwuid($<))[0] || "an unidentified user" ;

    $name =`finger $login | sed -n "s/Login.*:.*: //p"` ;
    if( $name eq "" ) { $name = $login ; }

    $date =  `date +"on %-e-%b-%Y at %H:%M"` ;

    $year =  `date +"%Y"` ;

    foreach $ag (@ARGV) {

	if( $ag =~ "^-s" ) {
	    $supress_section = 1 ;
	}
	elsif( $ag =~ "^-home" ) {
	    $homepage = 1 ;
	}
	else {

	    $preagtmp = $ag . ".tmpl~$$";
            $agtmp    = $ag . ".jsp~$$";

	    open(PRETMPL,">$preagtmp") or die "Unable to write $preagtmp\n";
	    print PRETMPL &doIncludes("$ag.tmpl");
	    close(PRETMPL);

	    open(TMPL,"<$preagtmp") or die "Unable to read $preagtmp\n";

	    open(HTML,">$agtmp") or die "Unable to open $agtmp\n" ;

	    $title=<TMPL> ;

	    $sectionhead = "XenoServers" ;
	    $copyright = "Computer Laboratory, University of Cambridge" ;
	    $breadcrumbline = "" ;
	    $commentcontact="<a href=\"mailto:pagemaster\@cl.cam.ac.uk\">pagemaster\@cl.cam.ac.uk</a>" ;

	    $process_headings = 1 ;
	    $tmp=<TMPL> ;
	    while( $process_headings ) {
		$process_headings = 0 ;

		if( $tmp =~ /^SECTION&(.*)$/ ) {
		    $sectionhead=$1 ;
		    $process_headings = 1 ;
		}

		if( $tmp =~ /^COMMENTS&(.*)$/ ) {
		    $commentcontact=$1 ;
		    $process_headings = 1 ;
		}

		if( $tmp =~ /^COPYRIGHT&(.*)$/ ) {
		    $copyright=$1 ;
		    $process_headings = 1 ;
		}

		if( $tmp =~ /^HEADERFILE&(.*)$/ ) {
		    $headerfile=$1 ;
		    $process_headings = 1 ;
		}

		if( $tmp =~ /^FOOTERFILE&(.*)$/ ) {
		    $footerfile=$1 ;
		    $process_headings = 1 ;
		}

		if( $tmp =~ /BREADCRUMB&.*/ ) {
		    @bread=split(/&/,$tmp) ;
		    @bwords=split(/ /, @bread[1]) ;
		    $bname=@bwords[0] ;
		    for( $i=1 ; $i <= $#bwords ; $i++ ){
			$bname = $bname . "&nbsp;" . @bwords[$i] ;
		    }
		    $breadcrumbline = $breadcrumbline . "&nbsp;&gt;&nbsp;<a href=\"" . @bread[2] . "\"class=\"bread\">" . $bname . "</a>" ; 
		    $process_headings = 1 ;
		}

		if( $process_headings ) {
		    $tmp=<TMPL> ;
		}
	    }

#### generate the final breadcrumb which is the current file itself
	    @path=split(/\//, $ag) ;
	    $localfilename=@path[$#path] . ".jsp" ;
	    @bwords=split(/ /, $title) ;
	    $bname=@bwords[0] ;
	    for( $i=1 ; $i <= $#bwords ; $i++ ){
		$bname = $bname . "&nbsp;" . @bwords[$i] ;
	    }
	    $breadcrumbline = $breadcrumbline . "&nbsp;&gt;&nbsp;<a href=\"" . $localfilename . "\" class=\"bread\">" . $bname . "</a>" ; 


#### if suppressing the section header then do so now
	    if( $supress_section ) {
		$sectionhead = "" ;
		$sectionbreak = "" ;
	    }

#### if homepage then do so now
	    if( $homepage ) {
		$breadcrumbline = "" ;
                $navigationwidth = 53;
                $navigationstring = "";
	    }


	    open(HEADER,"<$headerfile") or die "Unable to open $headerfile\n" ;
	    while(<HEADER>) {
		s/##TITLE##/$title/g ;
		s/##SECTION##/$sectionhead/g ;
		s/##SECTIONBREAK##/$sectionbreak/g ;
		s/##BREADCRUMBS##/$breadcrumbline/g ;
		s/##FILENAME##/$ag.jsp/g ;
		s/##DATE##/$date/g ;
		s/##OWNERNAME##/$name/g ;
		s/##OWNERUSERID##/$login/g ;
		s/##OWNEREMAIL##/$login\@cl.cam.ac.uk/g ;
		s/##COMMENTCONTACT##/$commentcontact/g ;
		s/##COPYRIGHT##/$copyright/g ;
		s/##YEAR##/$year/g ;
		s/##NAVIGATIONWIDTH##/$navigationwidth/g ;
		s/##NAVIGATIONSTRING##/$navigationstring/g ;
		print HTML $_ ;
	    }
	    close(HEADER) ;

	    $_ = $tmp ;
	    while(defined($_)) {
		s/##LISTSTART##/<ul>/g ;
		s/##ITEMHEAD##/<li>/g ;
		s/##ITEMBODY##/<br \/>/g ;
		s|##LISTEND##|</ul>|g ;
		s/##TITLE##/$title/g ;
		s/##SECTION##/$sectionhead/g ;
		s/##BREADCRUMBS##/$breadcrumbline/g ;
		s/##FILENAME##/$ag.jsp/g ;
		s/##DATE##/$date/g ;
		s/##OWNERNAME##/$name/g ;
		s/##OWNERUSERID##/$login/g ;
		s/##OWNEREMAIL##/$login\@cl.cam.ac.uk/g ;
		s/##COMMENTCONTACT##/$commentcontact/g ;
		s/##COPYRIGHT##/$copyright/g ;
		s/##YEAR##/$year/g ;
		s/##WHITESPACE##/$whitespace/g ;
		s/##GREYLINE1##/$greyline1/g ;
		s/##GREYLINE2##/$greyline2/g ;
		s/##GREYLINE3##/$greyline3/g ;
		s/##GREYLINE4##/$greyline4/g ;
		s/##GREYLINE14##/$greyline14/g ;
		print HTML $_ ;
		$_ = <TMPL>
		}
	    open(FOOTER,"<$footerfile") or die "Unable to open $footerfile\n" ;
	    while(<FOOTER>) {
		s/##TITLE##/$title/g ;
		s/##SECTION##/$sectionhead/g ;
		s/##BREADCRUMBS##/$breadcrumbline/g ;
		s/##FILENAME##/$ag.jsp/g ;
		s/##DATE##/$date/g ;
		s/##OWNERNAME##/$name/g ;
		s/##OWNERUSERID##/$login/g ;
		s/##OWNEREMAIL##/$login\@cl.cam.ac.uk/g ;
		s/##COMMENTCONTACT##/$commentcontact/g ;
		s/##COPYRIGHT##/$copyright/g ;
		s/##YEAR##/$year/g ;
		print HTML $_ ;
	    }
	    close(FOOTER) ;
	    close(HTML);
	    close(TMPL);

	    if( system "mv $agtmp $ag.jsp" ) {
		die "Unable to rename $agtmp to $ag.jsp\n" ; ;
	    }
	    if( system "rm $preagtmp" ) {
		die "Unable to remove $preagtmp\n" ; ;
	    }
	}
    }
}

sub usage
{
    print "Usage: install.pl [-s] <name>\n";
    print "       Installs web page <name>.jsp based on <name>.tmpl\n";
    print "       -s supresses the generation of any section title";
    print "          which says `Computer Laboratory' in the default" ;
    print "          case or is specified by SECTION& in the .tmpl file" ;
    exit;
}

sub doIncludes
{
    my $infile=$_[0];
    my $out="";
    my $tmp;
    my $incfile;
    my @lines;
    my $line;

    open(FIN,"<$infile") or die "doIncludes unable to read from $infile\n";
    @lines=<FIN>;
    close(FIN);
    foreach $line (@lines) {
	if( $line =~ /^INCLUDE&.*/ ) {
	    ($tmp,$incfile) = split(/&/,$line);
	    $out=$out.&doIncludes($incfile);
	} else {
	    $out=$out.$line;
	}
    }
    return $out;
}
