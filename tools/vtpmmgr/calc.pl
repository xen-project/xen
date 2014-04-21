#!/usr/bin/perl
use strict;
use Digest::SHA qw(sha1);
use Math::BigInt only => 'GMP';

my $s2 = Digest::SHA->new("SHA256");

# The key below is an example; its private key is (obviously) not private. This
# key must be protected at least as well as the vTPM's secrets, since it can
# approve the release of these secrets to a new TCB.  It may make sense to
# modify this script to use a TPM or some other hardware key storage device to
# hold the private key instead of holding the key in plaintext; such integration
# is beyond the scope of this example script.
#
# The public exponent of this key must be 65537 (0x10001); this is the default
# for TPM-generated RSA keys.
#
# The manage-tpmmgr.pl script expects the modulus of this RSA key to be
# available; this may be done using:
#
# open KEY, '>rsa-modulus-file';
# print KEY pack 'H*', $rsa_n;
# close KEY;

my $rsa_n = 'c1580b4ea118a6c2f0a56d5af59b080928a9de7267f824457a1e9d7216013b5a322ff67f72153cd4b58693284490aced3a85d81da909ffe544f934c80340020b5bf514e8850926c6ce3314c3283e33cb79cb6aecf041726782013d07f8171fde4ea8165c6a7050af534ffc1b11ae37ace2ed6436c626edb49bf5bd70ee71f74bf2c132a99e5a6427343dbe46829961755558386436ebea90959161295c78df0127d4e468f9a188b3c1e9b68e5b1e78a450ea437ac7930dab294ede8117f6849d53f11e0bbc8ccef44b7fc9ebd6d7c7532875b3225a9106961771001be618ab3f991ba18edc1b73d73b6b80b5df854f9c9113d0b0cd1fec81a85da3638745fd29';
my $rsa_d = '3229508daed80173f4114744e111beccf982d0d6a7c8c6484c3da3259535ee9b21083690ac1d7c71c742c9ed1994db7894c562e39716a4106c8ba738f936e310e563b96ff60c00c6757ae53918b8c2a158d100c5c63384a5fc21ac1ee42bc3b5de7c5788d4889d364f8c21e137fe162dc1964b78b682250bc5a6c4e686c6849cf8f0020f6ca383d784e5ffb85da56c2b89dc2e879509b1916c8b51f5907a0dbb7e2f9e5fabc500588ef7db6f78ba4605da86d907493648017ac46a1571ffe9b6a68babeeb277e3a96d346cddc996a94163f1e8393d88f710ff64369a62d3edfc62dbdeae57ee12a33adbb9b9d48d575158117f29fc991cbbbaaa4a47ee974f31';

sub rsa_sign {
	my $m = '1'.('ff'x218).'003021300906052b0e03021a05000414';
	$m .= unpack 'H*', sha1(shift);
	$m = Math::BigInt->from_hex($m);
	my $n = Math::BigInt->from_hex($rsa_n);
	my $e = Math::BigInt->from_hex($rsa_d);
	$m->bmodpow($e, $n);
	$m = $m->as_hex();
	$m =~ s/^0x//;
	$m =~ s/^/0/ while length $m < 512;
	pack 'H*', $m;
}

sub auth_update_file {
	my($dst,$seq) = (shift, shift);
	my(@plt, @pcrs, @kerns, $cfg);
	open my $update, '>', $dst or die $!;
	for (@_) {
		if (/^([0-9a-fA-F]+)=([0-9a-fA-F]+)$/) {
			push @pcrs, pack 'V', hex $1;
			push @plt, pack 'H*', $2;
		} elsif (/^[0-9a-fA-F]{40}$/) {
			push @kerns, pack 'H*', $_;
		} elsif (length $_ == 20) {
			push @kerns, $_;
		} else {
			print "Bad argument: $_";
			exit 1;
		}
	}
	$cfg = pack 'Q>', $seq;
	$cfg .= pack 'N/(a20)', @plt;
	$cfg .= pack 'N/(a20)', @kerns;

	printf "cfg_hash for %s: %s\n", $dst, Digest::SHA::sha1_hex($cfg);

	print $update rsa_sign($cfg);
	print $update $cfg;
	print $update map { pack 'n/a3', $_ } @pcrs;
	close $update;
}

my $out = shift;
my $seq = $ENV{SEQ} || time;

if (!$out) {
	print <<EOF;
Usage: $0 <output> {<pcrs>=<composite>}* {<kernel>}*
	<output> is the file that will contain the signed configuration
	<pcrs> is a 24-bit PCR mask in hexadecimal
	<composite> is a PCR_COMPOSITE_HASH in hexadecimal
	<kernel> is a 160-bit vTPM kernel hash in hexadecimal

The sequence number may be specified using the SEQ environment variable,
otherwise the current UNIX timestamp will be used.  The sequence number of a
vTPM group must increase on each update.

When the vTPM Manager is compiled without support for a domain builder, the
SHA-1 hash of the vTPM domain's XSM label is used in place of its kernel hash.

Example:
	A configuration with two valid command lines and one valid vTPM kernel
	PCRs 0-7 and 17-19 are being validated (static RTM and TBOOT).
	$0 auth-0 0e00ff=0593ecb564f532df6ef2f4d7272489da52c4c840 0e00ff=0593ecb564f532df6ef2f4d7272489da52c4c840 2bc65001d506ce6cd12cab90a4a2ad9040d641e1
EOF
	exit 0;
}
print "Sequence: $seq\n";

auth_update_file $out, $seq, @ARGV;
