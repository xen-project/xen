#!/usr/bin/perl
use strict;
use warnings;
use Digest::SHA;

# The /dev/tpm0 device can only be opened by one application at a time, so if
# the trousers daemon is running, this script will fail.
system "killall tcsd 2>/dev/null";
open my $tpm, '+>', '/dev/tpm0' or die "Could not open /dev/tpm0: $!";

sub tpm_cmd_raw {
	my $msg = join '', @_;
	my $rsp;
	print '<<', unpack('H*', $msg), "\n" if $ENV{V};
	syswrite $tpm, $msg;
	sysread $tpm, $rsp, 4096;
	print '>>', unpack('H*', $rsp), "\n" if $ENV{V};
	$rsp;
}

sub tpm_cmd_nohdr {
	my($type, $msg) = @_;
	my $head = pack 'nN', $type, 6 + length $msg;
	my $rsp = tpm_cmd_raw $head, $msg;
	my($rtype, $len, $stat, $reply) = unpack 'nNNa*', $rsp;
	die "incomplete response" if $len != 10 + length $reply;
	if ($stat) {
		print "TPM error: $stat\n";
		exit 1;
	}
	$reply;
}

sub cmd_list_group {
	my $group = shift;
	my($uuid, $pubk, $cfg_list) = unpack 'H32 a256 a*', tpm_cmd_nohdr 0x1C2,
		pack 'NN', 0x02000107, $group;
	$uuid = join "-", unpack 'a8a4a4a4a12', $uuid;
	my $pk_hash = Digest::SHA::sha1_hex($pubk);
	my $cfg_hash = Digest::SHA::sha1_hex($cfg_list);
	my($seq, @cfgs) = unpack 'Q> N/(H40) a*', $cfg_list;
	my @kerns = unpack "N/(H40)", pop @cfgs;
	print "Group $group ($uuid):\n";
	print " Public key hash: $pk_hash\n";
	print " Boot config #$seq ($cfg_hash)\n";
	print " Platforms:\n";
	print "  $_\n" for @cfgs;
	print " Kernels:\n";
	print "  $_\n" for @kerns;
	print " VTPMs:\n";

	my($nr, @vtpms) = unpack 'N(H32)*', tpm_cmd_nohdr 0x1C2, pack 'NNN', 0x02000201, $group, 0;
	if ($nr > @vtpms) {
		print "  TODO this list is cropped; needs multiple requests\n";
	}
	@vtpms = () if $nr == 0; # unpack returns an empty string in this case
	@vtpms = map { join "-", unpack 'a8a4a4a4a12', $_ } @vtpms;
	print "  $_\n" for @vtpms;
}

sub cmd_list {
	if (@_) {
		cmd_list_group $_[0];
	} else {
		my $nr = unpack 'N', tpm_cmd_nohdr 0x1C2, pack 'N', 0x02000101;
		cmd_list_group $_ for (0..($nr - 1));
	}
}

sub cmd_group_add {
	my $rsa_modfile = shift;
	my $ca_digest = "\0"x20;
	open MOD, $rsa_modfile or die $!;
	my $group_pubkey = join '', <MOD>;
	close MOD;

	my($uuid, $pubkey, $pksig) = unpack 'H32 a256 a*', tpm_cmd_nohdr 0x1C2, pack 'N(a*)*',
		0x02000102, $ca_digest, $group_pubkey;
	$uuid = join "-", unpack 'a8a4a4a4a12', $uuid;
	print "$uuid\n";
	mkdir "group-$uuid";
	open F, ">group-$uuid/aik.pub";
	print F $pubkey;
	close F;
	open F, ">group-$uuid/aik.priv-ca-data";
	print F $pksig;
	close F;

	# TODO certify the AIK using the pTPM's EK (privacy CA)
	# TODO escrow the recovery key for this group
}

sub cmd_group_del {
	my $nr = shift;
	tpm_cmd_nohdr 0x1C2, pack 'NN', 0x02000103, $nr;
}

sub cmd_group_update {
	my $nr = shift;
	open my $fh, '<', shift;
	my $cmd = join '', <$fh>;
	close $fh;

	tpm_cmd_nohdr 0x1C2, pack 'NNa*', 0x02000106, $nr, $cmd;
}

sub cmd_vtpm_add {
	my($group,$uuid) = @_;
	if ($uuid) {
		$uuid =~ s/-//g;
		$uuid = pack('H32', $uuid)."\0";
	} else {
		$uuid = '';
	}
	$uuid = unpack 'H32', tpm_cmd_nohdr 0x1C2, pack 'NNa*', 0x02000204, $group, $uuid;
	printf "%s\n", join "-", unpack 'a8a4a4a4a12', $uuid;
}

sub cmd_vtpm_del {
	my($uuid) = @_;
	$uuid =~ s/-//g;
	tpm_cmd_nohdr 0x1C2, pack 'NH32', 0x02000205, $uuid;
}

sub cmd_help {
	print <<EOH;
Usage: $0 <command> <args>

list [index]
	Lists the group identified by index, or all groups if omitted

group-add rsa-modulus-file
	Adds a new group to the TPM. The public key and Privacy CA data are
	output to group-UUID/aik.pub and group-UUID/aik.priv-ca-data, and the
	UUID is output to stdout.

group-update index signed-config-list-file
	Updates the permitted boot configuration list for an group

group-del index
	Deletes a group

vtpm-add index
	Adds a vTPM. Output: UUID

vtpm-del UUID
	Deletes a vTPM.

EOH
}

my $cmd = shift || 'help';
$cmd =~ s/-/_/g;
my $fn = $main::{"cmd_$cmd"};
if ($fn) {
	$fn->(@ARGV);
} else {
	print "Unknown command: $cmd\n";
	exit 1;
}
