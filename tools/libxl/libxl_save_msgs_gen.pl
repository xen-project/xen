#!/usr/bin/perl -w

use warnings;
use strict;
use POSIX;

our $debug = 0; # produce copious debugging output at run-time?

our @msgs = (
    # flags:
    #   s  - applicable to save
    #   r  - applicable to restore
    #   c  - function pointer in callbacks struct rather than fixed function
    #   x  - function pointer is in struct {save,restore}_callbacks
    #         and its null-ness needs to be passed through to the helper's xc
    #   W  - needs a return value; callback is synchronous
    #   A  - needs a return value; callback is asynchronous
    [  1, 'sr',     "log",                   [qw(uint32_t level
                                                 uint32_t errnoval
                                                 STRING context
                                                 STRING formatted)] ],
    [  2, 'sr',     "progress",              [qw(STRING context
                                                 STRING doing_what),
                                                'unsigned long', 'done',
                                                'unsigned long', 'total'] ],
    [  3, 'srcxA',  "suspend", [] ],
    [  4, 'srcxA',  "postcopy", [] ],
    [  5, 'srcxA',  "checkpoint", [] ],
    [  6, 'srcxA',  "wait_checkpoint", [] ],
    [  7, 'scxA',   "switch_qemu_logdirty",  [qw(uint32_t domid
                                              unsigned enable)] ],
    [  8, 'rcx',    "restore_results",       ['xen_pfn_t', 'store_gfn',
                                              'xen_pfn_t', 'console_gfn'] ],
    [  9, 'srW',    "complete",              [qw(int retval
                                                 int errnoval)] ],
);

#----------------------------------------

our %cbs;
our %func;
our %func_ah;
our @outfuncs;
our %out_decls;
our %out_body;
our %msgnum_used;

die unless @ARGV==1;
die if $ARGV[0] =~ m/^-/;

our ($intendedout) = @ARGV;

$intendedout =~ m/([a-z]+)\.([ch])$/ or die;
my ($want_ah, $ch) = ($1, $2);

my $declprefix = '';

foreach my $ah (qw(callout helper)) {
    $out_body{$ah} .=
        <<END_BOTH.($ah eq 'callout' ? <<END_CALLOUT : <<END_HELPER);
#include "libxl_osdeps.h"

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
END_BOTH

#include "libxl_internal.h"

END_CALLOUT

#include <xenctrl.h>
#include <xenguest.h>
#include "_libxl_save_msgs_${ah}.h"

END_HELPER
}

die $want_ah unless defined $out_body{$want_ah};

sub f_decl ($$$$) {
    my ($name, $ah, $c_rtype, $c_decl) = @_;
    $out_decls{$name} = "${declprefix}$c_rtype $name$c_decl;\n";
    $func{$name} = "$c_rtype $name$c_decl\n{\n" . ($func{$name} || '');
    $func_ah{$name} = $ah;
}

sub f_more ($$) {
    my ($name, $addbody) = @_;
    $func{$name} ||= '';
    $func{$name} .= $addbody;
    push @outfuncs, $name;
}

our $libxl = "libxl__srm";
our $callback = "${libxl}_callout_callback";
our $receiveds = "${libxl}_callout_received";
our $sendreply = "${libxl}_callout_sendreply";
our $getcallbacks = "${libxl}_callout_get_callbacks";
our $enumcallbacks = "${libxl}_callout_enumcallbacks";
sub cbtype ($) { "${libxl}_".$_[0]."_autogen_callbacks"; };

f_decl($sendreply, 'callout', 'void', "(int r, void *user)");

our $helper = "helper";
our $encode = "${helper}_stub";
our $allocbuf = "${helper}_allocbuf";
our $transmit = "${helper}_transmitmsg";
our $getreply = "${helper}_getreply";
our $setcallbacks = "${helper}_setcallbacks";

f_decl($allocbuf, 'helper', 'unsigned char *', '(int len, void *user)');
f_decl($transmit, 'helper', 'void',
       '(unsigned char *msg_freed, int len, void *user)');
f_decl($getreply, 'helper', 'int', '(void *user)');

sub typeid ($) { my ($t) = @_; $t =~ s/\W/_/; return $t; };

$out_body{'callout'} .= <<END;
static int bytes_get(const unsigned char **msg,
		     const unsigned char *const endmsg,
		     void *result, int rlen)
{
    if (endmsg - *msg < rlen) return 0;
    memcpy(result,*msg,rlen);
    *msg += rlen;
    return 1;
}

END
$out_body{'helper'} .= <<END;
static void bytes_put(unsigned char *const buf, int *len,
		      const void *value, int vlen)
{
    assert(vlen < INT_MAX/2 - *len);
    if (buf)
	memcpy(buf + *len, value, vlen);
    *len += vlen;
}

END

foreach my $simpletype (qw(int uint16_t uint32_t unsigned), 'unsigned long', 'xen_pfn_t') {
    my $typeid = typeid($simpletype);
    $out_body{'callout'} .= <<END;
static int ${typeid}_get(const unsigned char **msg,
                        const unsigned char *const endmsg,
                        $simpletype *result)
{
    return bytes_get(msg, endmsg, result, sizeof(*result));
}

END
    $out_body{'helper'} .= <<END;
static void ${typeid}_put(unsigned char *const buf, int *len,
			 const $simpletype value)
{
    bytes_put(buf, len, &value, sizeof(value));
}

END
}

$out_body{'callout'} .= <<END;
static int BLOCK_get(const unsigned char **msg,
                      const unsigned char *const endmsg,
                      const uint8_t **result, uint32_t *result_size)
{
    if (!uint32_t_get(msg,endmsg,result_size)) return 0;
    if (endmsg - *msg < *result_size) return 0;
    *result = (const void*)*msg;
    *msg += *result_size;
    return 1;
}

static int STRING_get(const unsigned char **msg,
                      const unsigned char *const endmsg,
                      const char **result)
{
    const uint8_t *data;
    uint32_t datalen;
    if (!BLOCK_get(msg,endmsg,&data,&datalen)) return 0;
    if (datalen == 0) return 0;
    if (data[datalen-1] != '\\0') return 0;
    *result = (const void*)data;
    return 1;
}

END
$out_body{'helper'} .= <<END;
static void BLOCK_put(unsigned char *const buf,
                      int *len,
		      const uint8_t *bytes, uint32_t size)
{
    uint32_t_put(buf, len, size);
    bytes_put(buf, len, bytes, size);
}

static void STRING_put(unsigned char *const buf,
		       int *len,
		       const char *string)
{
    size_t slen = strlen(string);
    assert(slen < INT_MAX / 4);
    assert(slen < (uint32_t)0x40000000);
    BLOCK_put(buf, len, (const void*)string, slen+1);
}

END

foreach my $sr (qw(save restore)) {
    f_decl("${getcallbacks}_${sr}", 'callout',
           "const ".cbtype($sr)." *",
           "(void *data)");

    f_decl("${receiveds}_${sr}", 'callout', 'int',
	   "(const unsigned char *msg, uint32_t len, void *user)");

    f_decl("${enumcallbacks}_${sr}", 'callout', 'unsigned',
           "(const ".cbtype($sr)." *cbs)");
    f_more("${enumcallbacks}_${sr}", "    unsigned cbflags = 0;\n");

    f_decl("${setcallbacks}_${sr}", 'helper', 'void',
           "(struct ${sr}_callbacks *cbs, unsigned cbflags)");

    f_more("${receiveds}_${sr}",
           <<END_ALWAYS.($debug ? <<END_DEBUG : '').<<END_ALWAYS);
    const unsigned char *const endmsg = msg + len;
    uint16_t mtype;
    if (!uint16_t_get(&msg,endmsg,&mtype)) return 0;
END_ALWAYS
    fprintf(stderr,"libxl callout receiver: got len=%u mtype=%u\\n",len,mtype);
END_DEBUG
    switch (mtype) {

END_ALWAYS

    $cbs{$sr} = "typedef struct ".cbtype($sr)." {\n";
}

foreach my $msginfo (@msgs) {
    my ($msgnum, $flags, $name, $args) = @$msginfo;
    die if $msgnum_used{$msgnum}++;

    my $f_more_sr = sub {
        my ($contents_spec, $fnamebase) = @_;
        $fnamebase ||= "${receiveds}";
        foreach my $sr (qw(save restore)) {
            $sr =~ m/^./;
            next unless $flags =~ m/$&/;
            my $contents = (!ref $contents_spec) ? $contents_spec :
                $contents_spec->($sr);
            f_more("${fnamebase}_${sr}", $contents);
        }
    };

    $f_more_sr->("    case $msgnum: { /* $name */\n");
    if ($flags =~ m/W/) {
        $f_more_sr->("        int r;\n");
    }

    my $c_rtype_helper = $flags =~ m/[WA]/ ? 'int' : 'void';
    my $c_rtype_callout = $flags =~ m/W/ ? 'int' : 'void';
    my $c_decl = '(';
    my $c_callback_args = '';

    f_more("${encode}_$name",
           <<END_ALWAYS.($debug ? <<END_DEBUG : '').<<END_ALWAYS);
    unsigned char *buf = 0;
    int len = 0, allocd = 0;

END_ALWAYS
    fprintf(stderr,"libxl-save-helper: encoding $name\\n");
END_DEBUG
    for (;;) {
        uint16_t_put(buf, &len, $msgnum /* $name */);
END_ALWAYS

    my @args = @$args;
    my $c_recv = '';
    my ($argtype, $arg);
    while (($argtype, $arg, @args) = @args) {
	my $typeid = typeid($argtype);
        my $c_args = "$arg";
        my $c_get_args = "&$arg";
	if ($argtype eq 'STRING') {
	    $c_decl .= "const char *$arg, ";
	    $f_more_sr->("        const char *$arg;\n");
        } elsif ($argtype eq 'BLOCK') {
            $c_decl .= "const uint8_t *$arg, uint32_t ${arg}_size, ";
            $c_args .= ", ${arg}_size";
            $c_get_args .= ",&${arg}_size";
	    $f_more_sr->("        const uint8_t *$arg;\n".
                         "        uint32_t ${arg}_size;\n");
	} else {
	    $c_decl .= "$argtype $arg, ";
	    $f_more_sr->("        $argtype $arg;\n");
	}
	$c_callback_args .= "$c_args, ";
	$c_recv.=
            "        if (!${typeid}_get(&msg,endmsg,$c_get_args)) return 0;\n";
        f_more("${encode}_$name", "	${typeid}_put(buf, &len, $c_args);\n");
    }
    $f_more_sr->($c_recv);
    $c_decl .= "void *user)";
    $c_callback_args .= "user";

    $f_more_sr->("        if (msg != endmsg) return 0;\n");

    my $c_callback;
    if ($flags !~ m/c/) {
        $c_callback = "${callback}_$name";
    } else {
        $f_more_sr->(sub {
            my ($sr) = @_;
            $cbs{$sr} .= "    $c_rtype_callout (*${name})$c_decl;\n";
            return
          "        const ".cbtype($sr)." *const cbs =\n".
            "            ${getcallbacks}_${sr}(user);\n";
                       });
        $c_callback = "cbs->${name}";
    }
    my $c_make_callback = "$c_callback($c_callback_args)";
    if ($flags !~ m/W/) {
	$f_more_sr->("        $c_make_callback;\n");
    } else {
        $f_more_sr->("        r = $c_make_callback;\n".
                     "        $sendreply(r, user);\n");
	f_decl($sendreply, 'callout', 'void', '(int r, void *user)');
    }
    if ($flags =~ m/x/) {
        my $c_v = "(1u<<$msgnum)";
        my $c_cb = "cbs->$name";
        $f_more_sr->("    if ($c_cb) cbflags |= $c_v;\n", $enumcallbacks);
        $f_more_sr->("    $c_cb = (cbflags & $c_v) ? ${encode}_${name} : 0;\n",
                     $setcallbacks);
    }
    $f_more_sr->("        return 1;\n    }\n\n");
    f_decl("${callback}_$name", 'callout', $c_rtype_callout, $c_decl);
    f_decl("${encode}_$name", 'helper', $c_rtype_helper, $c_decl);
    f_more("${encode}_$name",
"        if (buf) break;
        buf = ${helper}_allocbuf(len, user);
        assert(buf);
        allocd = len;
        len = 0;
    }
    assert(len == allocd);
    ${transmit}(buf, len, user);
");
    if ($flags =~ m/[WA]/) {
	f_more("${encode}_$name",
               (<<END_ALWAYS.($debug ? <<END_DEBUG : '').<<END_ALWAYS));
    int r = ${helper}_getreply(user);
END_ALWAYS
    fprintf(stderr,"libxl-save-helper: $name got reply %d\\n",r);
END_DEBUG
    return r;
END_ALWAYS
    }
}

print "/* AUTOGENERATED by $0 DO NOT EDIT */\n\n" or die $!;

foreach my $sr (qw(save restore)) {
    f_more("${enumcallbacks}_${sr}",
           "    return cbflags;\n");
    f_more("${receiveds}_${sr}",
           "    default:\n".
           "        return 0;\n".
           "    }");
    $cbs{$sr} .= "} ".cbtype($sr).";\n\n";
    if ($ch eq 'h') {
        print $cbs{$sr} or die $!;
        print "struct ${sr}_callbacks;\n";
    }
}

if ($ch eq 'c') {
    foreach my $name (@outfuncs) {
        next unless defined $func{$name};
        $func{$name} .= "}\n\n";
        $out_body{$func_ah{$name}} .= $func{$name};
        delete $func{$name};
    }
    print $out_body{$want_ah} or die $!;
} else {
    foreach my $name (sort keys %out_decls) {
        next unless $func_ah{$name} eq $want_ah;
        print $out_decls{$name} or die $!;
    }
}

close STDOUT or die $!;
