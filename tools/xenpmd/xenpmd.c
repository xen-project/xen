/*
 * xenpmd.c
 *
 * xen power management daemon - Facilitates power management 
 * functionality within xen guests.
 *
 * Copyright (c) 2008  Kamala Narasimhan 
 * Copyright (c) 2008  Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

/* Xen extended power management support provides HVM guest power management
 * features beyond S3, S4, S5.  For example, it helps expose system level 
 * battery status and battery meter information and in future will be extended
 * to include more power management support.  This extended power management 
 * support is enabled by setting xen_extended_power_mgmt to 1 or 2 in the HVM
 * config file.  When set to 2, non-pass through mode is enabled which heavily
 * relies on this power management daemon to glean battery information from 
 * dom0 and store it xenstore which would then be queries and used by qemu and 
 * passed to the guest when appropriate battery ports are read/written to.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <xenstore.h>

/* #define RUN_STANDALONE */
#define RUN_IN_SIMULATE_MODE

enum BATTERY_INFO_TYPE {
    BIF, 
    BST 
};

enum BATTERY_PRESENT {
    NO, 
    YES 
};

enum BATTERY_TECHNOLOGY {
    NON_RECHARGEABLE, 
    RECHARGEABLE 
};

struct battery_info {
    enum BATTERY_PRESENT    present;
    unsigned long           design_capacity;
    unsigned long           last_full_capacity;
    enum BATTERY_TECHNOLOGY battery_technology;
    unsigned long           design_voltage;
    unsigned long           design_capacity_warning;
    unsigned long           design_capacity_low;
    unsigned long           capacity_granularity_1;
    unsigned long           capacity_granularity_2;
    char                    model_number[32];
    char                    serial_number[32];
    char                    battery_type[32];
    char                    oem_info[32];
};

struct battery_status {
    enum BATTERY_PRESENT    present;
    unsigned long           state;
    unsigned long           present_rate;
    unsigned long           remaining_capacity;
    unsigned long           present_voltage;
};

static struct xs_handle *xs;

#ifdef RUN_IN_SIMULATE_MODE
    #define BATTERY_DIR_PATH "/tmp/battery"
    #define BATTERY_INFO_FILE_PATH "/tmp/battery/%s/info" 
    #define BATTERY_STATE_FILE_PATH "/tmp/battery/%s/state"
#else
    #define BATTERY_DIR_PATH "/proc/acpi/battery"
    #define BATTERY_INFO_FILE_PATH "/proc/acpi/battery/%s/info"
    #define BATTERY_STATE_FILE_PATH "/proc/acpi/battery/%s/state"
#endif

FILE *get_next_battery_file(DIR *battery_dir, 
                            enum BATTERY_INFO_TYPE battery_info_type)
{
    FILE *file = 0;
    struct dirent *dir_entries;
    char file_name[284];
    
    do 
    {
        dir_entries = readdir(battery_dir);
        if ( !dir_entries ) 
            return 0;
        if ( strlen(dir_entries->d_name) < 4 )
            continue;
        if ( battery_info_type == BIF ) 
            snprintf(file_name, sizeof(file_name), BATTERY_INFO_FILE_PATH,
                     dir_entries->d_name);
        else 
            snprintf(file_name, sizeof(file_name), BATTERY_STATE_FILE_PATH,
                     dir_entries->d_name);
        file = fopen(file_name, "r");
    } while ( !file );

    return file;
}

void set_attribute_battery_info(char *attrib_name,
                                char *attrib_value,
                                struct battery_info *info)
{
    if ( strstr(attrib_name, "present") ) 
    {
        if ( strstr(attrib_value, "yes") ) 
            info->present = YES;
        return;
    }

    if ( strstr(attrib_name, "design capacity warning") ) 
    {
        info->design_capacity_warning = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "design capacity low") ) 
    {
        info->design_capacity_low = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "design capacity") ) 
    { 
        info->design_capacity = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "last full capacity") ) 
    {
        info->last_full_capacity = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "design voltage") ) 
    {
        info->design_voltage = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "capacity granularity 1") ) 
    {
        info->capacity_granularity_1 = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "capacity granularity 2") ) 
    {
        info->capacity_granularity_2 = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "battery technology") ) 
    {
        if ( strncmp(attrib_value, "rechargeable",
                     strlen("rechargeable")) == 0 ) 
            info->battery_technology = RECHARGEABLE;
        else 
            info->battery_technology = NON_RECHARGEABLE;
        return;
    }

    if ( strstr(attrib_name, "model number") ) 
    {
        strncpy(info->model_number, attrib_value, 32);
        return;
    }

    if ( strstr(attrib_name, "serial number") ) 
    {
        strncpy(info->serial_number, attrib_value, 32);
        return;
    }

    if ( strstr(attrib_name, "battery type") ) 
    {
        strncpy(info->battery_type, attrib_value, 32);
        return;
    }

    if ( strstr(attrib_name, "OEM info") ) 
    {
        strncpy(info->oem_info, attrib_value, 32);
        return;
    }

    return;
}

void set_attribute_battery_status(char *attrib_name, 
                                  char *attrib_value,
                                  struct battery_status *status)
{
    if ( strstr(attrib_name, "charging state") ) 
    {
        /* Check this, below is half baked */
        if ( strstr(attrib_value, "charged") ) 
            status->state = 0;
        else 
            status->state = 1;
        return;
    }

    if ( strstr(attrib_name, "present rate") ) 
    {
        status->present_rate = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "remaining capacity") ) 
    {
        status->remaining_capacity = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "present voltage") ) 
    {
        status->present_voltage = strtoull(attrib_value, NULL, 10);
        return;
    }

    if ( strstr(attrib_name, "present") ) 
    {
        if ( strstr(attrib_value, "yes") ) 
            status->present = YES;
        return;
    }
}

void parse_battery_info_or_status(char *line_info,
                                  enum BATTERY_INFO_TYPE type,
                                  void *info_or_status)
{
    char attrib_name[128];
    char attrib_value[64];
    char *delimiter;
    unsigned long length;

    length = strlen(line_info);
    delimiter = (char *) strchr( line_info, ':');
    if ( (!delimiter) || (delimiter == line_info) ||
         (delimiter == line_info + length) ) 
        return;

    strncpy(attrib_name, line_info, delimiter-line_info);
    while ( *(delimiter+1) == ' ' ) 
    {
        delimiter++;
        if ( delimiter+1 == line_info + length)
            return;
    }
    strncpy(attrib_value, delimiter+1, 
            (unsigned long)line_info + length -(unsigned long)delimiter); 
    
    if ( type == BIF ) 
        set_attribute_battery_info(attrib_name, attrib_value,
                                   (struct battery_info *)info_or_status);
    else 
        set_attribute_battery_status(attrib_name, attrib_value,
                                     (struct battery_status *)info_or_status);

    return;
}

int get_next_battery_info_or_status(DIR *battery_dir,
                                    enum BATTERY_INFO_TYPE type,
                                    void *info_or_status)
{
    FILE *file;
    char line_info[256];

    if  ( !info_or_status )
        return 0;

    if (type == BIF) 
        memset(info_or_status, 0, sizeof(struct battery_info));
    else 
        memset(info_or_status, 0, sizeof(struct battery_status));

    file = get_next_battery_file(battery_dir, type);
    if ( !file )
        return 0;

    while ( fgets(line_info, sizeof(line_info), file) != NULL ) 
        parse_battery_info_or_status(line_info, type, info_or_status);

    fclose(file);
    return 1;
}

#ifdef RUN_STANDALONE
void print_battery_info(struct battery_info *info)
{
    printf("present:                %d\n", info->present);
    printf("design capacity:        %d\n", info->design_capacity);
    printf("last full capacity:     %d\n", info->last_full_capacity);
    printf("battery technology:     %d\n", info->battery_technology);
    printf("design voltage:         %d\n", info->design_voltage);
    printf("design capacity warning:%d\n", info->design_capacity_warning);
    printf("design capacity low:    %d\n", info->design_capacity_low);
    printf("capacity granularity 1: %d\n", info->capacity_granularity_1);
    printf("capacity granularity 2: %d\n", info->capacity_granularity_2);
    printf("model number:           %s\n", info->model_number);
    printf("serial number:          %s\n", info->serial_number);
    printf("battery type:           %s\n", info->battery_type);
    printf("OEM info:               %s\n", info->oem_info);
}
#endif /*RUN_STANDALONE*/

void write_ulong_lsb_first(char *temp_val, unsigned long val)
{
    snprintf(temp_val, 9, "%02x%02x%02x%02x", (unsigned int)val & 0xff, 
    (unsigned int)(val & 0xff00) >> 8, (unsigned int)(val & 0xff0000) >> 16, 
    (unsigned int)(val & 0xff000000) >> 24);
}

void write_battery_info_to_xenstore(struct battery_info *info)
{
    char val[1024], string_info[256];

    xs_mkdir(xs, XBT_NULL, "/pm");
   
    memset(val, 0, 1024);
    memset(string_info, 0, 256);
    /* write 9 dwords (so 9*4) + length of 4 strings + 4 null terminators */
    snprintf(val, 3, "%02x", 
             (unsigned int)(9*4 +
                            strlen(info->model_number) +
                            strlen(info->serial_number) +
                            strlen(info->battery_type) +
                            strlen(info->oem_info) + 4));
    write_ulong_lsb_first(val+2, info->present);
    write_ulong_lsb_first(val+10, info->design_capacity);
    write_ulong_lsb_first(val+18, info->last_full_capacity);
    write_ulong_lsb_first(val+26, info->battery_technology);
    write_ulong_lsb_first(val+34, info->design_voltage);
    write_ulong_lsb_first(val+42, info->design_capacity_warning);
    write_ulong_lsb_first(val+50, info->design_capacity_low);
    write_ulong_lsb_first(val+58, info->capacity_granularity_1);
    write_ulong_lsb_first(val+66, info->capacity_granularity_2);

    snprintf(string_info, 256, "%02x%s%02x%s%02x%s%02x%s", 
             (unsigned int)strlen(info->model_number), info->model_number,
             (unsigned int)strlen(info->serial_number), info->serial_number,
             (unsigned int)strlen(info->battery_type), info->battery_type,
             (unsigned int)strlen(info->oem_info), info->oem_info);
    strncat(val+73, string_info, 1024-73-1);
    xs_write(xs, XBT_NULL, "/pm/bif", 
             val, 73+8+strlen(info->model_number)+strlen(info->serial_number)+
             strlen(info->battery_type)+strlen(info->oem_info)+1);
}

int write_one_time_battery_info(void)
{
    DIR *dir;
    int ret = 0;
    struct battery_info info;
    
    dir = opendir(BATTERY_DIR_PATH);
    if ( !dir )
        return 0;

    while ( get_next_battery_info_or_status(dir, BIF, (void *)&info) ) 
    {
#ifdef RUN_STANDALONE
        print_battery_info(&info);
#endif
        if ( info.present == YES ) 
        {
            write_battery_info_to_xenstore(&info);
            ret = 1;
            break; /* rethink this... */
        }
    }

    closedir(dir);
    return ret;
}

#ifdef RUN_STANDALONE
void print_battery_status(struct battery_status *status)
{
    printf("present:                     %d\n", status->present);
    printf("Battery state                %d\n", status->state);
    printf("Battery present rate         %d\n", status->present_rate);
    printf("Battery remining capacity    %d\n", status->remaining_capacity);
    printf("Battery present voltage      %d\n", status->present_voltage);
}
#endif /*RUN_STANDALONE*/

void write_battery_status_to_xenstore(struct battery_status *status)
{
    char val[35];

    xs_mkdir(xs, XBT_NULL, "/pm");

    memset(val, 0, 35);
    snprintf(val, 3, "%02x", 16);
    write_ulong_lsb_first(val+2, status->state);
    write_ulong_lsb_first(val+10, status->present_rate);
    write_ulong_lsb_first(val+18, status->remaining_capacity);
    write_ulong_lsb_first(val+26, status->present_voltage);

    xs_write(xs, XBT_NULL, "/pm/bst", val, 35);
}

int wait_for_and_update_battery_status_request(void)
{
    DIR *dir;
    int ret = 0;
    unsigned int count;
    struct battery_status status;

    while ( true )
    {
        /* KN:@TODO - It is rather inefficient to not cache the file handle.
         *  Switch to caching file handle. 
         */
        dir = opendir(BATTERY_DIR_PATH);
        if ( !dir )
            return 0;

        while ( get_next_battery_info_or_status(dir, BST, (void *)&status) ) 
        {
#ifdef RUN_STANDALONE
            print_battery_status(&status);
#endif
            if ( status.present == YES ) 
            {
                write_battery_status_to_xenstore(&status);
                ret = 1;
                /* rethink this; though I have never seen, there might be
                 * systems out there with more than one battery device 
                 * present
                 */
                break;
            }
        }
        closedir(dir);
        xs_watch(xs, "/pm/events", "refreshbatterystatus");
        xs_read_watch(xs, &count); 
    }

    return ret;
}

/* Borrowed daemonize from xenstored - Initially written by Stevens. */
static void daemonize(void)
{
    pid_t pid;

    if ( (pid = fork()) < 0 )
        exit(1);

    if ( pid != 0 )
        exit(0);

    setsid();

    if ( (pid = fork()) < 0 )
        exit(1);

    if ( pid != 0 )
        exit(0);

    if ( chdir("/") == -1 )
        exit(1);

    umask(0);
}

int main(int argc, char *argv[])
{
#ifndef RUN_STANDALONE
    daemonize();
#endif
    xs = (struct xs_handle *)xs_daemon_open();
    if ( xs == NULL ) 
        return -1;

    if ( write_one_time_battery_info() == 0 ) 
    {
        xs_daemon_close(xs);
        return -1;
    }

    wait_for_and_update_battery_status_request();
    xs_daemon_close(xs);
    return 0;
}

