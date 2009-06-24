#!/usr/bin/perl -w

#############################################################################################################
#                                                                                                           #
#  Developed by Ingard Mevåg @ Oslo University College, spring 2007                                         #
#  ingard [at] mevaag  [dot] no                                                                             #
#                                                                                                           #
#  This work is licensed under the Creative Commons Attribution-Noncommercial-Share Alike 3.0 License.      #
#  To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/3.0/ or send a letter #
#  to Creative Commons, 171 Second Street, Suite 300, San Francisco, California, 94105, USA.                #
#                                                                                                           #
#############################################################################################################

use strict;
# http://search.cpan.org/~rjray/RPC-XML-0.59/lib/RPC/XML/Client.pm
require RPC::XML;
require RPC::XML::Client;

# for debug purposes
#use Data::Dumper;

##### CONFIG ######

my %xenhosts = ("192.0.2.10" => {"port" => "9363"}, 
					 "192.0.2.11" => {"port" => "9363"}, 
					 "192.0.2.12" => {"port" => "9363"}, 
					 "192.0.2.13" => {"port" => "9363"});

##### CONFIG END ###

##### STATIC VARS #####
my %host_info;

#######################
sub apiconnect
{
	foreach my $xenhost (keys %xenhosts)
	{
		my $xen = RPC::XML::Client->new("http://$xenhost:$xenhosts{$xenhost}{'port'}");
		my $session = $xen->simple_request("session.login_with_password", "user","");
		if (! $session)
		{
			print "Can't connect to $xenhost :(\n";
			$xenhosts{$xenhost} = {'xen' => $xen, 'session' => ""};
		}
		else
		{
			$xenhosts{$xenhost} = {'xen' => $xen, 'session' => $session->{'Value'}};
			print "Connected successfully to $xenhost..\n";
		}
	}
}

sub validate_response
{
	my ($result_ref) = @_;
	if ($result_ref->{'Status'} eq "Success")
	{
		return $result_ref->{'Value'};
	}
	else
	{
		# status = Failure !
#		die ("xmlrpc failed! ErrorDescription: $result_ref->{'ErrorDescription'}[1] -> $result_ref->{'ErrorDescription'}[0]");
		print "xmlrpc failed! ErrorDescription: $result_ref->{'ErrorDescription'}[1] -> $result_ref->{'ErrorDescription'}[0]\n";
	}
}

sub get_host_cpu_utilisation
{
	my ($xen, $session, $host_name, $host_ref) = @_;
	my $host_cpu_ref = validate_response($xen->simple_request("host.get_host_CPUs", $session, $host_ref));
	foreach (@$host_cpu_ref)
	{
		my $host_cpu_utilisation = validate_response($xen->simple_request("host_cpu.get_utilisation", $session, $_));
		$host_info{$host_name}{'cpus'}{$_} = $host_cpu_utilisation;
		print "     CPUiNFO: $host_cpu_utilisation\n";
	}
}

sub get_host_pif_utilisation
{
	my ($xen, $session, $host_name, $host_ref) = @_;

# This method isnt implemented yet it seems so using PIF.get_all for now.. 
# This will break when xen is made cluster aware..
#	my $host_pif_ref = validate_response($xen->simple_request("host.get_PIFs", $session, $host_ref)); 
	my $host_pif_ref = validate_response($xen->simple_request("PIF.get_all", $session));
	foreach (@$host_pif_ref)
	{
		my $host_pif_device = validate_response($xen->simple_request("PIF.get_device", $session, $_));
		my $host_pif_metrics_ref = validate_response($xen->simple_request("PIF.get_metrics", $session, $_));

# Whats the best solution performancewise?
# Collecting stats from get_records, or pulling individually?

#		my $host_pif_record = validate_response($xen->simple_request("PIF_metrics.get_record", $session, $host_pif_metrics_ref));
#		my $host_pif_io_read = $host_pif_record->{'io_read_kbs'};
#		my $host_pif_io_write = $host_pif_record->{'io_write_kbs'};
		my $host_pif_io_read = validate_response($xen->simple_request("PIF_metrics.get_io_read_kbs", $session, $host_pif_metrics_ref));
		my $host_pif_io_write = validate_response($xen->simple_request("PIF_metrics.get_io_write_kbs", $session, $host_pif_metrics_ref));

		$host_info{$host_name}{'pifs'}{$host_pif_device} = {'read' => $host_pif_io_read, 'write' => $host_pif_io_write};
		print "     PiFiNFO: $host_pif_device READ: $host_pif_io_read - WRITE: $host_pif_io_write\n";
#		$host_info{$host_name}{'pifs'}{$host_pif_device}{'read'} = $host_pif_io_read;
#		$host_info{$host_name}{'pifs'}{$host_pif_device}{'write'} = $host_pif_io_write;
	}
}

sub get_host_mem_utilisation
{
	my ($xen, $session, $host_name, $host_ref) = @_;
	my $host_metrics_ref = validate_response($xen->simple_request("host.get_metrics", $session, $host_ref)); 
	my $host_mem_total =  validate_response($xen->simple_request("host_metrics.get_memory_total", $session, $host_metrics_ref)) / 1024 / 1024;
	my $host_mem_free =  validate_response($xen->simple_request("host_metrics.get_memory_free", $session, $host_metrics_ref)) / 1024 / 1024;
	$host_info{$host_name}{'memory'} = {'total' => $host_mem_total, 'free' => $host_mem_free};
	print "     MEMiNFO: Total: $host_mem_total MB - Free: $host_mem_free MB\n";
}

sub get_vm_mem_info
{
	my ($xen, $session, $host_name, $vm_ref, $vm_name_label) = @_;
	my $vm_mem_stat_max = validate_response($xen->simple_request("VM.get_memory_static_max",$session,$vm_ref));
	my $vm_mem_stat_min = validate_response($xen->simple_request("VM.get_memory_static_min",$session,$vm_ref));
	my $vm_mem_dyn_max = validate_response($xen->simple_request("VM.get_memory_dynamic_max",$session,$vm_ref));
	my $vm_mem_dyn_min = validate_response($xen->simple_request("VM.get_memory_dynamic_min",$session,$vm_ref));

	# not implemented yet.. We'll do this at the same time as getting cpu utilisation
	# in the get_vm_metrics sub instead..
	#my $vm_metrics_ref = validate_response($xen->simple_request("VM.get_metrics",$session,$vm_ref));
	#my $vm_mem_actual = validate_response($xen->simple_request("VM_metrics.get_memory_actual",$session,$vm_metrics_ref));

	$host_info{$host_name}{'vms'}{$vm_name_label}{'memory'} = {'static_max' => $vm_mem_stat_max,
								  'static_min' => $vm_mem_stat_min,
								  'dynamic_max' => $vm_mem_dyn_max,
								  'dynamic_min' => $vm_mem_dyn_min};

	# xm list uses the dynamic min var as far as i can tell.. or?
	# Lets print the memactual info instead of this... I'll do that in the get_vm_metrics sub instead..
	# print "  |- MEMiNFO: Dynamic Min: $vm_mem_dyn_min - Actually in use: $vm_mem_actual\n";
}

sub get_vm_metrics
{
	my ($xen, $session, $host_name, $vm_ref, $vm_name_label) = @_;
	my $vm_metrics_ref = validate_response($xen->simple_request("VM.get_metrics",$session,$vm_ref));
	
	my %vm_vcpu_utilisation = %{validate_response($xen->simple_request("VM_metrics.get_vcpus_utilisation",$session,$vm_metrics_ref))};
	for my $tempcpu (keys %vm_vcpu_utilisation)
	{
		print "  |- CPUiNFO: $tempcpu - $vm_vcpu_utilisation{$tempcpu}\n";
		$host_info{$host_name}{'vms'}{$vm_name_label}{'vcpus'} = {$tempcpu => $vm_vcpu_utilisation{$tempcpu}};
	}
	my $vm_mem_actual = validate_response($xen->simple_request("VM_metrics.get_memory_actual",$session,$vm_metrics_ref)) / 1024 / 1024;
	$host_info{$host_name}{'vms'}{$vm_name_label}{'memory'}{'actual'} = "$vm_mem_actual";
	print "  |- MEMiNFO: Actually in use: $vm_mem_actual MB\n";
}

sub get_vm_vif_utilisation
{
	my ($xen, $session, $host_name, $vm_ref, $vm_name_label) = @_;
	my $vm_vifs = validate_response($xen->simple_request("VM.get_VIFs",$session,$vm_ref));
	foreach (@$vm_vifs)
	{
		my $vif_device = validate_response($xen->simple_request("VIF.get_device",$session,$_));
		my $vif_io_read = validate_response($xen->simple_request("VIF_metrics.get_io_read_kbs", $session, $_));
		my $vif_io_write = validate_response($xen->simple_request("VIF_metrics.get_io_write_kbs", $session, $_));
		$host_info{$host_name}{'vms'}{$vm_name_label}{'vifs'}{$vif_device} = {'read' => $vif_io_read, 'write' => $vif_io_write};
		print "  |- ViFiNFO: $vif_device READ: $vif_io_read - WRITE: $vif_io_write\n";
	}
}

sub get_vm_vbd_utilisation
{
	my ($xen, $session, $host_name, $vm_ref, $vm_name_label) = @_;
	my $vm_vbds = validate_response($xen->simple_request("VM.get_VBDs",$session,$vm_ref));
	foreach (@$vm_vbds)
	{
		my $vbd_device = validate_response($xen->simple_request("VBD.get_device",$session,$_));
		my $vbd_io_read = validate_response($xen->simple_request("VBD_metrics.get_io_read_kbs", $session, $_));
		my $vbd_io_write = validate_response($xen->simple_request("VBD_metrics.get_io_write_kbs", $session, $_));
		$host_info{$host_name}{'vms'}{$vm_name_label}{'vbds'}{$vbd_device} = {'read' => $vbd_io_read, 'write' => $vbd_io_write};
		print "  |- VBDiNFO: $vbd_device READ: $vbd_io_read - WRITE: $vbd_io_write\n";
	}
}


sub get_vm_type
{
	my ($xen, $session, $host_name, $vm_ref, $vm_name_label) = @_;
	# not running response through validate_response() here to stop it from crashing..
	#
	# api docs says if this (following) field is set, its a HVM domain.
	my $vm_bootloader_results = $xen->simple_request("VM.get_HVM_boot_policy",$session,$vm_ref);
	if ("$vm_bootloader_results->{'Status'}" eq "Success")
	{
		if ("$vm_bootloader_results->{'Value'}" ne "")
		{
			$host_info{$host_name}{'vms'}{$vm_name_label}{'type'} = "HVM";
		}
		else
		{
			$host_info{$host_name}{'vms'}{$vm_name_label}{'type'} = "PV";
		}
	}
	else
	{
		# However, xen 3.0.4 doest support this part of the api, so afaik I can get the difference with: 
		my $vm_pv_kernel_results = $xen->simple_request("VM.get_PV_kernel",$session,$vm_ref);
		# which is something like:
		# 'PV_kernel': '/boot/vmlinuz-2.6.18-xen',
		# or
		# 'PV_kernel': 'hvmloader',
		if ("$vm_pv_kernel_results->{'Value'}" =~ m/hvm/i)
		{
			$host_info{$host_name}{'vms'}{$vm_name_label}{'type'} = "HVM";
		}
		else
		{
			$host_info{$host_name}{'vms'}{$vm_name_label}{'type'} = "PV";
		}
	}
}

sub get_complete_info
{	
	my %all_vms;
	foreach my $xenhost (sort keys %xenhosts)
	{
		next unless $xenhosts{$xenhost}{'session'};
		my $xen = $xenhosts{$xenhost}{'xen'};
		my $session = $xenhosts{$xenhost}{'session'};
		print "_______________________\n## $xenhost ##\n-----------------------\n";
	
		my $host_ref = validate_response($xen->simple_request("session.get_this_host", $session));
		
		my $host_name = validate_response($xen->simple_request("host.get_name_label", $session, $host_ref));
		$xenhosts{$xenhost}{'hostname'} = $host_name;
		$host_info{$host_name}{'ip'} = $xenhost;
		
		get_host_cpu_utilisation($xen, $session, $host_name, $host_ref);

		get_host_mem_utilisation($xen, $session, $host_name, $host_ref);
	
		get_host_pif_utilisation($xen, $session, $host_name, $host_ref);
	
	
		my $all_vm_refs = validate_response($xen->simple_request("host.get_resident_VMs",$session, $host_ref));
		
		foreach my $vm_ref (@$all_vm_refs)
		{
			my $vm_name_label = validate_response($xen->simple_request("VM.get_name_label",$session,$vm_ref));
			get_vm_type($xen,$session,$host_name,$vm_ref,$vm_name_label);
			
			my $vm_id = validate_response($xen->simple_request("VM.get_domid",$session,$vm_ref));

			print "vm: $vm_id\t$vm_name_label\ttype: $host_info{$host_name}{'vms'}->{$vm_name_label}{'type'}\n";
			
			# vm_metrics includes both mem_actual & cpu utilisation
			# So we'll add all stats found in that class in one go..
			get_vm_metrics($xen,$session,$host_name,$vm_ref,$vm_name_label);
#			get_vm_cpu_utilisation($xen,$session,$host_name,$vm_ref,$vm_name_label);

			# all other mem stats are added seperately..
			# This might not be needed at all as xen doesnt have functionality to
			# resize mem for a VM atm (afaik)
			get_vm_mem_info($xen,$session,$host_name,$vm_ref,$vm_name_label);
	
			get_vm_vif_utilisation($xen,$session,$host_name,$vm_ref,$vm_name_label);
			
			get_vm_vbd_utilisation($xen,$session,$host_name,$vm_ref,$vm_name_label);
			
			$all_vms{$vm_name_label} = "" unless ("$vm_name_label" eq "Domain-0");
		}
		print "\n";
	}
	# Debug: Uncomment to see the nested datastructure..
	#print Dumper(%host_info);
}



apiconnect();
get_complete_info();
