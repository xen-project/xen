#!/usr/bin/python


# Basic Pool creation tests

from XmTestLib import xapi
from XmTestLib import *


session = xapi.connect()
host_ref = session.xenapi.host.get_all()[0]
pools = session.xenapi.host.get_resident_cpu_pools(host_ref)
if len(pools) != 1:
       SKIP("Only Pool-0 have to be created for this test")


# check extension of host object
host_recs = session.xenapi.host.get_all_records()
host_rec = host_recs[host_recs.keys()[0]]
if len(host_recs.keys()) != 1 or not host_rec.has_key("resident_cpu_pools") or \
               len(host_rec["resident_cpu_pools"]) != 1:
       FAIL("Missing or wrong field 'resident_cpu_pools' in host record")


# check extension of host_cpu object
host_cpu_recs = session.xenapi.host_cpu.get_all_records()
assigned_cpus = [ cpu for cpu in host_cpu_recs.values() if len(cpu["cpu_pool"]) > 0 ]
unassigned_cpus = session.xenapi.host_cpu.get_unassigned_cpus()
if len(host_cpu_recs) - len(assigned_cpus) != len(unassigned_cpus):
       FAIL("Wrong host_cpu count values; CPUS total: %d, CPUS ass: %d, CPUS unass: %d" % (
                       len(host_cpu_recs), len(assigned_cpus), len(unassigned_cpus)))

for cpu_rec in host_cpu_recs.values():
       cpu_pool = session.xenapi.host_cpu.get_cpu_pool(cpu_rec['uuid'])
       if cpu_pool != cpu_rec['cpu_pool']:
               FAIL("Inconsistency of cpu_pool ref between host_cpu record (%s) "
                        "and get_cpu_pool (%s)" % (cpu_rec['cpu_pool'], cpu_pool))


# create / modify / remove managed cpu pools
pool1_cfg = { 'name_label' : 'Pool-1',
              'name_description' : 'new pool',
              'auto_power_on' : False,
              'ncpu' : '3',
              'sched_policy' : 'credit',
              'proposed_CPUs' : ['1','2'],
              'other_config' : { 'xmtest' : True },
            }
pool1 = session.xenapi.cpu_pool.create(pool1_cfg)
pool1_rec = session.xenapi.cpu_pool.get_record(pool1)
for k in pool1_cfg.keys():
       if pool1_rec[k] != pool1_cfg[k]:
               FAIL("Create error Pool-1 (create config %s, current config: %s, key: %s)" % (
                               pool1_cfg, pool1_rec, k))

pool_all = session.xenapi.cpu_pool.get_all()
if len(pool_all) != 2:
       FAIL("cpu_pool.get_all() returns '%d', expected '2'" % len(pool_all))

pool_all = session.xenapi.cpu_pool.get_all_records()
if len(pool_all) != 2:
       FAIL("cpu_pool.get_all_records() returns '%d', expected '2'" % len(pool_all))

if pool1 != session.xenapi.cpu_pool.get_by_name_label(pool1_cfg['name_label'])[0]:
       FAIL("cpu_pool.get_by_name_label() returns wrong value")

if pool1 != session.xenapi.cpu_pool.get_by_uuid(pool1):
       FAIL("cpu_pool.get_by_uuid() returns wrong value")

if session.xenapi.cpu_pool.get_activated(pool1):
       FAIL("cpu_pool.get_activated() returns 'true' instead of 'false'")

if pool1_cfg['auto_power_on'] != session.xenapi.cpu_pool.get_auto_power_on(pool1):
       FAIL("cpu_pool.get_auto_power_on() returns wrong value")

if len(session.xenapi.cpu_pool.get_host_CPUs(pool1)) != 0:
       FAIL("cpu_pool.get_host_CPUs has to return an empty list")

if pool1_cfg['name_label'] != session.xenapi.cpu_pool.get_name_label(pool1):
       FAIL("cpu_pool.get_name_label() returns wrong value")

if pool1_cfg['name_description'] != session.xenapi.cpu_pool.get_name_description(pool1):
       FAIL("cpu_pool.get_name_description() returns wrong value")

if pool1_cfg['ncpu'] != session.xenapi.cpu_pool.get_ncpu(pool1):
       FAIL("cpu_pool.get_ncpu() returns wrong value")

cfg_len = len(pool1_cfg['proposed_CPUs'])
api_len = len(session.xenapi.cpu_pool.get_proposed_CPUs(pool1))
if cfg_len != api_len:
       FAIL("cpu_pool.get_proposed_CPUs() returns wrong value; cfg_cnt: %s, api_cnt:%s" % (cfg_len, api_len))

other_config = session.xenapi.cpu_pool.get_other_config(pool1)
if pool1_cfg['other_config']['xmtest'] != other_config.get('xmtest'):
       FAIL("cpu_pool.get_other_config() returns wrong value")

if session.xenapi.cpu_pool.get_resident_on(pool1) != session.xenapi.host.get_all()[0]:
       FAIL("cpu_pool.get_resident_on() returns wrong value")

if pool1_cfg['sched_policy'] != session.xenapi.cpu_pool.get_sched_policy(pool1):
       FAIL("cpu_pool.get_sched_policy() returns wrong value")

if len(session.xenapi.cpu_pool.get_started_VMs(pool1)) != 0:
       FAIL("cpu_pool.get_started_VMs() returns wrong value")

if pool1 != session.xenapi.cpu_pool.get_uuid(pool1):
       FAIL("cpu_pool.get_uuid() returns wrong value")

session.xenapi.cpu_pool.set_auto_power_on(pool1, True)
if not session.xenapi.cpu_pool.get_auto_power_on(pool1):
       FAIL("cpu_pool.get_auto_power_on() returns wrong value")

session.xenapi.cpu_pool.set_proposed_CPUs(pool1, [4])
if '4' not in session.xenapi.cpu_pool.get_proposed_CPUs(pool1):
       FAIL("cpu_pool.get_proposed_CPUs() returns wrong value; (set_proposed_CPUs)")

session.xenapi.cpu_pool.add_to_proposed_CPUs(pool1, 5)
val = session.xenapi.cpu_pool.get_proposed_CPUs(pool1)
if '5' not in val:
       FAIL("cpu_pool.get_proposed_CPUs() returns wrong value; %s not in %s" % ('5',val))

session.xenapi.cpu_pool.remove_from_proposed_CPUs(pool1, 5)
val = session.xenapi.cpu_pool.get_proposed_CPUs(pool1)
if '5' in val:
       FAIL("cpu_pool.get_proposed_CPUs() returns wrong value; %s in %s" % ('5',val))

session.xenapi.cpu_pool.set_name_label(pool1, 'New-Pool-1')
if 'New-Pool-1' != session.xenapi.cpu_pool.get_name_label(pool1):
       FAIL("cpu_pool.get_name_label() returns wrong value")

session.xenapi.cpu_pool.set_ncpu(pool1, 4)
if '4' != session.xenapi.cpu_pool.get_ncpu(pool1):
       FAIL("cpu_pool.get_ncpu() returns wrong value")

session.xenapi.cpu_pool.set_other_config(pool1, {'test' : 'ok'})
other_config = session.xenapi.cpu_pool.get_other_config(pool1)
if other_config.get('test') != 'ok':
       FAIL("cpu_pool.get_other_config() returns wrong value")

session.xenapi.cpu_pool.add_to_other_config(pool1, 'new_entry', 'added')
other_config = session.xenapi.cpu_pool.get_other_config(pool1)
if other_config.get('new_entry') != 'added':
       FAIL("cpu_pool.get_other_config() returns wrong value")

session.xenapi.cpu_pool.remove_from_other_config(pool1, 'new_entry')
other_config = session.xenapi.cpu_pool.get_other_config(pool1)
if other_config.get('new_entry') != None:
       FAIL("cpu_pool.get_other_config() returns wrong value")

session.xenapi.cpu_pool.set_sched_policy(pool1, 'credit')
if 'credit' != session.xenapi.cpu_pool.get_sched_policy(pool1):
       FAIL("cpu_pool.get_sched_policy() returns wrong value")

session.xenapi.cpu_pool.destroy(pool1)
if pool1 in  session.xenapi.cpu_pool.get_all():
       FAIL("cpu_pool.destroy() has not removed pool")

