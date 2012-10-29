#ifndef _MCHECK_AMD_H
#define _MCHECK_AMD_H

enum mcheck_type amd_k8_mcheck_init(struct cpuinfo_x86 *c);
enum mcheck_type amd_f10_mcheck_init(struct cpuinfo_x86 *c);

int mc_amd_recoverable_scan(uint64_t status);
int mc_amd_addrcheck(uint64_t status, uint64_t misc, int addrtype);

#endif
