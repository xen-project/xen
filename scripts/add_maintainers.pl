#!/usr/bin/perl -w
# (c) 2018, Lars Kurth <lars.kurth@citrix.com>
#
# Add maintainers to patches generated with git format-patch
#
# Usage: perl scripts/add_maintainers.pl [OPTIONS] -patchdir <patchdir>
#
# Prerequisites: Execute
#                git format-patch ... -o <patchdir> ...
#
#                ./scripts/get_maintainer.pl is present in the tree
#
# Licensed under the terms of the GNU GPL License version 2

use strict;

use Getopt::Long qw(:config no_auto_abbrev);
use File::Basename;
use List::MoreUtils qw(uniq);
use IO::Handle;

sub getmaintainers ($$$);
sub gettagsfrompatch ($$$;$);
sub normalize ($$);
sub insert ($$$$);
sub hastag ($$);

# Tool Variables
my $tool = $0;
my $get_maintainer = $tool;
$get_maintainer =~ s/add_maintainers/get_maintainer/;
my $usage = <<EOT;
OPTIONS:
--------
USAGE: $tool [options] (--patchdir | -d) <patchdir>

  --reroll-count <n> | -v <n>
    Choose patch files for specific version. This results into the
    following filters on <patchdir>
    0: default - *.patch
    >1: v<n>*.patch

  --patchcc (header|commit|comment|none) | -p (header|commit|comment|none)

    Insert CC lines into *.patch files in the specified location.
    When `none` is specified, the *.patch files are not changed.
    See LOCATIONS for a definition of the various locations.

    The default is `header`.

  --covercc (header|end|none) | -c (header|end|none)

    Insert CC lines into cover letter in the specified location. See
    When `none` is specified, the cover letter is not changed.
    LOCATIONS for a definition of the various locations.

    The default is `header`.

  --tagscc

    In addition to the output of get_maintainer.pl, include email
    addresses from commit tags (e.g., Reviewed-by, Tested-by, ...) in
    the list of CC lines to insert.

    These extra lines will be inserted as specified by the --patchcc
    and --covercc options. When used with `--patchcc commit`,
    this will duplicate e-mail addresses in the commit message.

  --tags | -t

    As above, but the insert location is special-cased: e-mail addresses
    will always be inserted into the `header` of patches and the cover letter.

  --get-maintainers=<program>

    Run <program> instead of $get_maintainer.
    (Passing `true` for <program> suppresses the usual computation
    of CCs, from files touched by patches and MAINTAINERS.)

  --arg <argument> | -a <argument> ...
    Arguments passed on to get_maintainer.pl
    This option can be used multiple times, e.g. -a <a1> -a <a2> ...

  --verbose
    Show more output

  --help | -h
    Show this help information

LOCATIONS:
----------

  *.patch and cover letters files consist of several sections relevant
   to processing:

  <header>:  This is the email header containing email related information
             It ends with the Subject: line

  <commit>: This is the email body that ends up in the commit message.
             It ends with ---.  CC lines added here will be checked
             into the git tree on commit.  Only applicable to normal
             patch files.

  <comment>: This is the 'comment for reviewers' section, after the
             --- but before the diff actually starts. CCs added here
             are processed by git send-email, but are not checked into
             the git tree on commit.  Only applicable to normal patch
             files.

  <end>:     The part of a cover letter just before `-- ` (which normally
             begins a diffstat).  Only applicable to cover letters.

  DEFAULT BEHAVIOUR:
  ------------------
  * get_maintainer is called on each patch to find email addresses
    of maintainers/reviewers for that patch
  * All of the above addresses are added to the CC mail headers
    of each patch
  * All of the above addresses are added to the CC mail headers
    of the cover letter

WORKFLOW:
---------
  This script is intended to be used as part of the following workflow

  Step 1: git format-patch ... -o <patchdir> ...
  Step 2: ./scripts/add_maintainers.pl -d <patchdir>
          This overwrites *.patch files in <patchdir> but makes a backup
  Step 3: git send-email -to xen-devel\@lists.xenproject.org <patchdir>/*.patch
EOT

# Constants and functions related to LOCATIONS

# Constants for -p|--patchcc and -c|--covercc option processing
my @plocations= ("header", "commit", "comment", "none");
my @clocations= ("header", "end", "none");

# Hash is used to determine which mode value maps onto which search string
my %inssearch = (
    "header"  => "Date:",          # Insert before Date:
    "commit"  => "Signed-off-by:", # Insert before Signed-off-by:
    "comment" => "---",            # Insert after ---
    "end"     => "-- ",            # Insert before '-- '
);

# Hash is used to determine whether for a given mode we insert CCs after
# the search string or before
my %insafter = (
    "header"  => 0,
    "commit"  => 0,
    "comment" => 1,
    "end"     => 0,
);

# The following subroutines take a areference to arrays of
# - @header: contains CCs from *-by: tags and TOs from mailing lists
# - @cc:  contains all other CC's
# It will then apply the corect locations on the input file

sub applylocation_header ($$$) {
    my ($file, $rheader, $rcc) = @_;
    my $insert = join("\n", uniq (@$rheader, @$rcc));
    insert($file , $insert, $inssearch{header}, $insafter{header});
}

sub applymixedlocation ($$$$) {
    my ($file, $rheader, $rcc, $mode) = @_;
    my $header = join("\n", @$rheader);
    my $cc  = join("\n", @$rcc);
    # Insert snippets into files
    insert($file , $cc, $inssearch{$mode}, $insafter{$mode});
    # The header
    insert($file , $header, $inssearch{header}, $insafter{header});
}

sub applylocation_commit($$$) {
    my ($file, $rheader, $rcc) = @_;
    applymixedlocation($file, $rheader, $rcc, "commit");
}

# Use a different name to make sure perl doesn't throw a syntax error
sub applylocation_comment ($$$) {
    my ($file, $rheader, $rcc) = @_;
    applymixedlocation($file, $rheader, $rcc, "comment");
}

sub applylocation_end ($$$) {
    my ($file, $rheader, $rcc) = @_;
    applymixedlocation($file, $rheader, $rcc, "end");
}

sub applylocation_none ($$$) {
    return;
}

# Hash for location functions
my %applylocation = (
    "header"  => \&applylocation_header,
    "commit"  => \&applylocation_commit,
    "comment" => \&applylocation_comment,
    "end"     => \&applylocation_end,
    "none"    => \&applylocation_none,
);

# Arguments / Options
my $help = 0;
my $patch_dir = 0;
my @get_maintainer_args = ();
my $verbose = 0;
my $rerollcount = 0;
my $tags = 0;
my $tagscc = 0;
my $plocation = "header";
my $clocation = "header";

# Constants
# Keep these as constants, in case we want to make these configurable
# in future
my $CC                  = "Cc:"; # Note: git-send-mail requires Cc:
my $TO                  = "To:";
my $cover_letter        = "0000-cover-letter.patch";
my $patch_ext           = ".patch";
my $maintainers         = "MAINTAINERS";

if (!GetOptions(
                'd|patchdir=s'     => \$patch_dir,
                'v|reroll-count=i' => \$rerollcount,
                'p|patchcc=s'      => \$plocation,
                'c|covercc=s'      => \$clocation,
                't|tags'           => \$tags,
                'tagscc'           => \$tagscc,
                'a|arg=s'          => \@get_maintainer_args,
                'get-maintainers=s' => \$get_maintainer,
                'verbose'          => \$verbose,
                'h|help'           => \$help,
                )) {
    die "$tool: invalid argument - use --help if necessary\n";
}

if ($help) {
    print $usage;
    exit 0;
}

if (!$patch_dir) {
    die "$tool: Directory -d|--patchdir not specified\n";
}

if (! -e $patch_dir) {
    die "$tool: Directory $patch_dir does not exist\n";
}

# Calculate the $patch_prefix
my $patch_prefix = "";
if ($rerollcount == 0) {
    # If the user didn't specify -v and we are here, then
    # - either the directory is empty
    # - or it contains some version of a patch
    # In this case we search for the first patch and
    # work out the version
    $!=0;
    my @coverletters = glob($patch_dir.'/*'.$patch_ext);
    if (!$! && scalar @coverletters) {
        if ($coverletters[0] =~ /\/v([0-9]+)-\Q$cover_letter\E/) {
            $rerollcount = $1;
        }
    }
}
if ($rerollcount > 0) {
    $patch_prefix = "v".$rerollcount."-";
}

if ( ! grep $_ eq $plocation, @plocations) {
    die "$tool: Invalid -p|--patchcc value\n";
}
if ( ! grep $_ eq $clocation, @clocations) {
    die "$tool: Invalid -c|--covercc value\n";
}

# Get the list of patches
my $has_cover_letter = 0;
my $cover_letter_file;
my $pattern = $patch_dir.'/'.$patch_prefix.'[0-9][0-9][0-9][0-9]*'.$patch_ext;

$!=0;
my @patches = glob($pattern);
if ($!) {
    die "$tool: Directory $patch_dir contains no patches\n";
}
if (!scalar @patches) {
    die "$tool: Directory $patch_dir contains no matching patches.\n".
         "Please try --reroll-count <n> | -v <n>\n";
}

# Do the actual processing
my $file;
my @combined_header;
my @combined_cc;

foreach my $file (@patches) {
    if ($file =~ /\/\Q$patch_prefix$cover_letter\E/) {
        $has_cover_letter = 1;
        $cover_letter_file = $file;
    } else {
        my @header;     # To: lists returned by get_maintainers.pl
        my @headerpatch;# To: entries in *.patch
                        #
                        # Also includes CC's from tags as we do not want
                        # entries in the body such as
                        # CC: lars.kurth@citrix.com
                        # ...
                        # Tested-by: lars.kurth@citrix.com

        my @cc;         # Cc: maintainers returned by get_maintainers.pl
        my @ccpatch;    # Cc: entries in *.patch
        my @extrapatch; # Cc: for AB, RB, RAB in *.patch

        print "Processing: ".basename($file)."\n";

        # Read tags from output of get_maintainers.pl
        # Lists go into @header and everything else into @cc
        getmaintainers($file, \@header, \@cc);

        # Read all lines with CC & TO from the patch file (these will
        # likely come from the commit message). Also read tags.
        gettagsfrompatch($file, \@headerpatch, \@ccpatch, \@extrapatch);

        # With -t|--tags only add @extrapatch to @header and @combined_header
        # With --tagscc treat tags as CC that came from the *.patch file
        if ($tags && !$tagscc) {
            # Copy these always onto the TO related arrays
            push @header, @extrapatch;
            push @combined_header, @extrapatch;
        } elsif ($tagscc) {
            # Treat these as if they came from CC's
            push @ccpatch, @extrapatch;
            push @combined_cc, @extrapatch;
        }

        # In this section we normalize the lists. We remove entries
        # that are already in the patch, from @cc and @to
        my @header_only = normalize(\@header, \@headerpatch);
        my @cc_only  = normalize(\@cc, \@ccpatch);

        # Apply the location
        $applylocation{$plocation}($file, \@header_only, \@cc_only);
    }
}

# Deal with the cover letter
if ($has_cover_letter) {
    my @headerpatch;   # Entries inserted at the header
    my @ccpatch;    # Cc: entries in *.patch

    print "Processing: ".basename($cover_letter_file)."\n";

    # Read all lines with CC & TO from the patch file such that subsequent
    # calls don't lead to duplication
    gettagsfrompatch($cover_letter_file, \@headerpatch, \@ccpatch);

    # In this section we normalize the lists. We remove entries
    # that are already in the patch, from @cc and @to
    my @header_only = normalize(\@combined_header, \@headerpatch);
    my @cc_only  = normalize(\@combined_cc, \@ccpatch);

    # Apply the location
    $applylocation{$clocation}($cover_letter_file, \@header_only, \@cc_only);

    print "\nDon't forget to add the subject and message to ".
          $cover_letter_file."\n";
}

print "Then perform:\n".
      "git send-email -to xen-devel\@lists.xenproject.org ".
      $patch_dir.'/'.$patch_prefix."*.patch"."\n";

exit 0;

my $getmailinglists_done = 0;
my @mailinglists = ();

sub getmailinglists () {
   # Read mailing list from MAINTAINERS file and copy
   # a list of e-mail addresses to @mailinglists
    if (!$getmailinglists_done) {
        if (-e $maintainers) {
            my $fh;
            my $line;
            open($fh, "<", $maintainers) or die $!;
            while (my $line = <$fh>) {
                chomp $line;
                if ($line =~ /^L:[[:blank:]]+/m) {
                   push @mailinglists, $';
                }
            }
            $fh->error and die $!;
            close $fh or die $!;
        } else {
            print "Warning: file '$maintainers' does not exist\n";
            print "Warning: Mailing lists will be treated as CC's\n";
        }
    # Don't try again, even if the MAINTAINERS file does not exist
    $getmailinglists_done = 1;
    # Remove any duplicates
    @mailinglists = uniq @mailinglists;
    }
}

sub ismailinglist ($) {
    my ($check) = @_;
    # Get the mailing list information
    getmailinglists();
    # Do the check
    if ( grep { $_ eq $check} @mailinglists) {
        return 1;
    }
    return 0;
}

sub getmaintainers ($$$) {
    my ($file, $rto, $rcc) = @_;
    my $fh;
    open($fh, "-|", $get_maintainer, @get_maintainer_args, $file)
        or die "Failed to open '$get_maintainer'\n";
    while(my $line = <$fh>) {
        chomp $line;
        # Keep lists and CC's separately as we dont want them in
        # the commit message under a Cc: line
        if (ismailinglist($line)) {
            push @$rto, $TO." ".$line;
            push @combined_header, $TO." ".$line;
        } else {
            push @$rcc, $CC." ".$line;
            push @combined_cc, $CC." ".$line;
        }
    }
    $fh->error and die $!;
    close $fh or die $!;
}

sub gettagsfrompatch ($$$;$) {
    my ($file, $rto, $rcc, $rextra) = @_;
    my $fh;

    open($fh, "<", $file)
        or die "Failed to open '$file'\n";
    while(my $line = <$fh>) {
        chomp $line;
        my $nline;

        if (hastag($line, $TO)) {
            push @$rto, $line;
            push @combined_header, $line;
        }
        if (hastag($line, $CC)) {
            push @$rcc, $line;
            push @combined_cc, $line;
        }
        # If there is an $rextra, then get various tags and add
        # email addresses to the CC list
        if ($rextra && $line =~ /^[-0-9a-z]+-by:[[:blank:]]+/mi) {
            push @$rextra, $CC." ".$';
        }
    }
    $fh->error and die $!;
    close $fh or die $!;
}

sub hastag ($$) {
    my ($line, $tag) = @_;
    if ($line =~ m{^\Q$tag\E}i) {
        return 1;
    }
    return 0;
}

sub normalize ($$) {
    my ($ra, $rb) = @_;
    # This function is used to normalize lists of tags or CC / TO lists
    # It returns a list of the unique elements
    # in @$ra, excluding any which are in @$rb.
    # Comparisons are case-insensitive.
    my @aonly = ();
    my %seen;
    my $item;

    foreach $item (@$rb) {
        $seen{lc($item)} = 1;
    }
    foreach $item (@$ra) {
        unless ($seen{lc($item)}++) {
            # it's not in %seen, so add to @aonly
            push @aonly, $item;
        }
    }

    return @aonly;
}

sub readfile ($) {
    my ($file) = @_;
    my $fh;
    my $content;
    open($fh, "<", $file)
         or die "Could not open file '$file' $!";
    $content = do { local $/; <$fh> };
    $fh->error and die $!;
    close $fh or die $!;

    return $content;
}

sub writefile ($$) {
    my ($content, $file) = @_;
    my $fh;
    open($fh, ">", "$file.tmp")
         or die "Could not open file '$file.tmp' $!";
    print $fh $content or die $!;
    close $fh or die $!;
    rename "$file.tmp", $file or die "Could not rename '$file' into place $!";
}

sub insert ($$$$) {
    my ($file, $insert, $delimiter, $insafter) = @_;
    my $content;

    if ($insert eq "") {
        # Nothing to insert
        return;
    }
    # Read file
    $content = readfile($file) or die $!;

    # Split the string and generate new content
    if ($content =~ /^\Q$delimiter\E/mi) {
        if ($insafter) {
            writefile($`.$delimiter."\n".$insert."\n".$', $file);

            if ($verbose) {
                print "\nInserted into ".basename($file).' after "'.
                      $delimiter."'"."\n-----\n".$insert."\n-----\n";
            }
        } else {
            writefile($`.$insert."\n".$delimiter.$', $file);

            if ($verbose) {
                print "\nInserted into ".basename($file).' before "'.
                      $delimiter."'"."\n-----\n".$insert."\n-----\n";
            }
        }

    } else {
       print "Error: Didn't find '$delimiter' in '$file'\n";
    }
}
