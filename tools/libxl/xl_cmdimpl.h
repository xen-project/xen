/*
 * Author Yang Hongyang <yanghy@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

int main_vcpulist(int argc, char **argv);
int main_info(int argc, char **argv);
int main_cd_eject(int argc, char **argv);
int main_cd_insert(int argc, char **argv);
int main_console(int argc, char **argv);
int main_pcilist(int argc, char **argv);
int main_pcidetach(int argc, char **argv);
int main_pciattach(int argc, char **argv);
int main_restore(int argc, char **argv);
int main_migrate_receive(int argc, char **argv);
int main_save(int argc, char **argv);
int main_migrate(int argc, char **argv);
int main_pause(int argc, char **argv);
int main_unpause(int argc, char **argv);
int main_destroy(int argc, char **argv);
int main_list(int argc, char **argv);
int main_list_vm(int argc, char **argv);
int main_create(int argc, char **argv);
int main_button_press(int argc, char **argv);
int main_vcpupin(int argc, char **argv);
int main_vcpuset(int argc, char **argv);
int main_memset(int argc, char **argv);
int main_sched_credit(int argc, char **argv);
int main_domid(int argc, char **argv);
int main_domname(int argc, char **argv);
int main_rename(int argc, char **argv);
int main_trigger(int argc, char **argv);
int main_sysrq(int argc, char **argv);
int main_top(int argc, char **argv);

void help(char *command);
