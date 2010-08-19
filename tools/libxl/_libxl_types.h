#ifndef __LIBXL_TYPES_H
#define __LIBXL_TYPES_H

typedef struct {
    libxl_uuid uuid;
    uint32_t domid;
    uint8_t running:1;
    uint8_t blocked:1;
    uint8_t paused:1;
    uint8_t shutdown:1;
    uint8_t dying:1;

    /*
     * Valid SHUTDOWN_* value from xen/sched.h iff (shutdown||dying).
     *
     * Otherwise set to a value guaranteed not to clash with any valid
     * SHUTDOWN_* constant.
     */
    unsigned int shutdown_reason;

    uint64_t max_memkb;
    uint64_t cpu_time;
    uint32_t vcpu_max_id;
    uint32_t vcpu_online;
} libxl_dominfo;

typedef struct {
    uint32_t poolid;
} libxl_poolinfo;

typedef struct {
    libxl_uuid uuid;
    uint32_t domid;
} libxl_vminfo;

typedef struct {
    int xen_version_major;
    int xen_version_minor;
    char *xen_version_extra;
    char *compiler;
    char *compile_by;
    char *compile_domain;
    char *compile_date;
    char *capabilities;
    char *changeset;
    unsigned long virt_start;
    unsigned long pagesize;
    char *commandline;
} libxl_version_info;

typedef struct {
    bool hvm;
    bool hap;
    bool oos;
    int ssidref;
    char *name;
    libxl_uuid uuid;
    libxl_key_value_list xsdata;
    libxl_key_value_list platformdata;
    uint32_t poolid;
    char *poolname;
} libxl_domain_create_info;

typedef struct {
    /*
     * Path is always set if the file refernece is valid. However if
     * mapped is true then the actual file may already be unlinked.
     */
    char *path;
    int mapped;
    void *data;
    size_t size;
} libxl_file_reference;

/*
 * Instances of libxl_file_reference contained in this struct which
 * have been mapped (with libxl_file_reference_map) will be unmapped
 * by libxl_domain_build/restore. If either of these are never called
 * then the user is responsible for calling
 * libxl_file_reference_unmap.
 */
typedef struct {
    int max_vcpus;
    int cur_vcpus;
    int tsc_mode;
    uint32_t max_memkb;
    uint32_t target_memkb;
    uint32_t video_memkb;
    uint32_t shadow_memkb;
    bool disable_migrate;
    libxl_file_reference kernel;
    int hvm;
    union {
        struct {
            bool pae;
            bool apic;
            bool acpi;
            bool nx;
            bool viridian;
            char *timeoffset;
            bool hpet;
            bool vpt_align;
            int timer_mode;
        } hvm;
        struct {
            uint32_t   slack_memkb;
            const char *bootloader;
            const char *bootloader_args;
            char *cmdline;
            libxl_file_reference ramdisk;
            const char *features;
        } pv;
    } u;
} libxl_domain_build_info;

typedef struct {
    uint32_t store_port;
    unsigned long store_mfn;
    uint32_t console_port;
    unsigned long console_mfn;
} libxl_domain_build_state;

typedef struct {
    int domid;
    libxl_uuid uuid; /* this is use only with stubdom, and must be different from the domain uuid */
    char *dom_name;
    char *device_model;
    char *saved_state;
    libxl_qemu_machine_type type;
    int videoram; /* size of the videoram in MB */
    bool stdvga; /* stdvga enabled or disabled */
    bool vnc; /* vnc enabled or disabled */
    char *vnclisten; /* address:port that should be listened on for the VNC server if vnc is set */
    char *vncpasswd; /* the VNC password */
    int vncdisplay; /* set VNC display number */
    bool vncunused; /* try to find an unused port for the VNC server */
    char *keymap; /* set keyboard layout, default is en-us keyboard */
    bool sdl; /* sdl enabled or disabled */
    bool opengl; /* opengl enabled or disabled (if enabled requires sdl enabled) */
    bool nographic; /* no graphics, use serial port */
    char *serial; /* serial port re-direct to pty deivce */
    char *boot; /* boot order, for example dca */
    bool usb; /* usb support enabled or disabled */
    char *usbdevice; /* enable usb mouse: tablet for absolute mouse, mouse for PS/2 protocol relative mouse */
    char *soundhw; /* enable sound hardware */
    bool apic; /* apic enabled or disabled */
    int vcpus; /* max number of vcpus */
    int vcpu_avail; /* vcpus actually available */
    int xen_platform_pci; /* enable/disable the xen platform pci device */
    libxl_string_list extra; /* extra parameters pass directly to qemu, NULL terminated */
    /* Network is missing */
} libxl_device_model_info;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    bool vnc; /* vnc enabled or disabled */
    char *vnclisten; /* address:port that should be listened on for the VNC server if vnc is set */
    char *vncpasswd; /* the VNC password */
    int vncdisplay; /* set VNC display number */
    bool vncunused; /* try to find an unused port for the VNC server */
    char *keymap; /* set keyboard layout, default is en-us keyboard */
    bool sdl; /* sdl enabled or disabled */
    bool opengl; /* opengl enabled or disabled (if enabled requires sdl enabled) */
    char *display;
    char *xauthority;
} libxl_device_vfb;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
} libxl_device_vkb;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    libxl_console_consback consback;
    libxl_domain_build_state *build_state;
    char *output;
} libxl_device_console;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    char *physpath;
    libxl_disk_phystype phystype;
    char *virtpath;
    int unpluggable;
    int readwrite;
    int is_cdrom;
} libxl_device_disk;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    int mtu;
    char *model;
    libxl_mac mac;
    struct in_addr ip;
    char *bridge;
    char *ifname;
    char *script;
    libxl_nic_type nictype;
} libxl_device_nic;

typedef struct {
    int devid;
    libxl_mac front_mac;
    libxl_mac back_mac;
    uint32_t backend_domid;
    uint32_t domid;
    uint32_t trusted:1;
    uint32_t back_trusted:1;
    uint32_t filter_mac:1;
    uint32_t front_filter_mac:1;
    uint32_t pdev;
    uint32_t max_bypasses;
    char *bridge;
} libxl_device_net2;

typedef struct {
    union {
        unsigned int value;
        struct {
            unsigned int reserved1:2;
            unsigned int reg:6;
            unsigned int func:3;
            unsigned int dev:5;
            unsigned int bus:8;
            unsigned int reserved2:7;
            unsigned int enable:1;
        };
    };
    unsigned int domain;
    unsigned int vdevfn;
    unsigned int vfunc_mask;
    bool msitranslate;
    bool power_mgmt;
} libxl_device_pci;

typedef struct {
    char *backend;
    uint32_t backend_id;
    char *frontend;
    uint32_t frontend_id;
    int devid;
    int state;
    int evtch;
    int rref;
} libxl_diskinfo;

typedef struct {
    char *backend;
    uint32_t backend_id;
    char *frontend;
    uint32_t frontend_id;
    int devid;
    int state;
    char *script;
    libxl_mac mac;
    int evtch;
    int rref_tx;
    int rref_rx;
} libxl_nicinfo;

typedef struct {
    uint32_t vcpuid; /* vcpu's id */
    uint32_t cpu; /* current mapping */
    uint8_t online:1; /* currently online (not hotplugged)? */
    uint8_t blocked:1; /* blocked waiting for an event? */
    uint8_t running:1; /* currently scheduled on its CPU? */
    uint64_t vcpu_time; /* total vcpu time ran (ns) */
    libxl_cpumap cpumap; /* current cpu's affinities */
} libxl_vcpuinfo;

typedef struct {
    uint32_t threads_per_core;
    uint32_t cores_per_socket;

    uint32_t max_cpu_id;
    uint32_t nr_cpus;
    uint32_t cpu_khz;

    uint64_t total_pages;
    uint64_t free_pages;
    uint64_t scrub_pages;

    uint32_t nr_nodes;
    libxl_hwcap hw_cap;
    uint32_t phys_cap;
}  libxl_physinfo;

typedef struct {
    int weight;
    int cap;
} libxl_sched_credit;

typedef struct {
    char *backend;
    uint32_t backend_id;
    char *frontend;
    uint32_t frontend_id;
    int devid;
    int state;
    libxl_mac mac;
    int trusted;
    libxl_mac back_mac;
    int filter_mac;
} libxl_net2info;

#endif /* __LIBXL_TYPES_H */
