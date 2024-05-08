#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <xenctrl.h>

static xc_interface *xch;

static const char intel_id[] = "GenuineIntel";
static const char   amd_id[] = "AuthenticAMD";

static void show_curr_cpu(FILE *f)
{
    int ret;
    struct xenpf_pcpu_version cpu_ver = { .xen_cpuid = 0 };
    struct xenpf_ucode_revision ucode_rev = { .cpu = 0 };
    /* Always exit with 2 when called during usage-info */
    int exit_code = (f == stderr) ? 2 : 1;

    ret = xc_get_cpu_version(xch, &cpu_ver);
    if ( ret )
    {
        fprintf(stderr, "Failed to get CPU information. (err: %s)\n",
                strerror(errno));
        exit(exit_code);
    }

    ret = xc_get_ucode_revision(xch, &ucode_rev);
    if ( ret )
    {
        fprintf(stderr, "Failed to get microcode information. (err: %s)\n",
                strerror(errno));
        exit(exit_code);
    }

    /*
     * Print signature in a form that allows to quickly identify which ucode
     * blob to load, e.g.:
     *
     *      Intel:   /lib/firmware/intel-ucode/06-55-04
     *      AMD:     /lib/firmware/amd-ucode/microcode_amd_fam19h.bin
     */
    if ( memcmp(cpu_ver.vendor_id, intel_id,
                sizeof(cpu_ver.vendor_id)) == 0 )
    {
        fprintf(f,
                "CPU signature %02x-%02x-%02x (raw 0x%08x) pf %#x revision 0x%08x\n",
                cpu_ver.family, cpu_ver.model, cpu_ver.stepping,
                ucode_rev.signature, ucode_rev.pf, ucode_rev.revision);
    }
    else if ( memcmp(cpu_ver.vendor_id, amd_id,
                     sizeof(cpu_ver.vendor_id)) == 0 )
    {
        fprintf(f,
                "CPU signature %02x-%02x-%02x (raw 0x%08x) revision 0x%08x\n",
                cpu_ver.family, cpu_ver.model, cpu_ver.stepping,
                ucode_rev.signature, ucode_rev.revision);
    }
    else
    {
        fprintf(f, "Unsupported CPU vendor: %s\n", cpu_ver.vendor_id);
        exit(exit_code);
    }
}

int main(int argc, char *argv[])
{
    int fd, ret;
    char *filename, *buf;
    size_t len;
    struct stat st;

    xch = xc_interface_open(NULL, NULL, 0);
    if ( xch == NULL )
    {
        fprintf(stderr, "Error opening xc interface. (err: %s)\n",
                strerror(errno));
        exit(1);
    }

    if ( argc < 2 )
    {
        fprintf(stderr,
                "xen-ucode: Xen microcode updating tool\n"
                "Usage: %s [<microcode file> | show-cpu-info]\n", argv[0]);
        show_curr_cpu(stderr);
        exit(2);
    }

    if ( !strcmp(argv[1], "show-cpu-info") )
    {
        show_curr_cpu(stdout);
        return 0;
    }

    filename = argv[1];
    fd = open(filename, O_RDONLY);
    if ( fd < 0 )
    {
        fprintf(stderr, "Could not open %s. (err: %s)\n",
                filename, strerror(errno));
        exit(1);
    }

    if ( fstat(fd, &st) != 0 )
    {
        fprintf(stderr, "Could not get the size of %s. (err: %s)\n",
                filename, strerror(errno));
        exit(1);
    }

    len = st.st_size;
    buf = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( buf == MAP_FAILED )
    {
        fprintf(stderr, "mmap failed. (error: %s)\n", strerror(errno));
        exit(1);
    }

    errno = 0;
    ret = xc_microcode_update(xch, buf, len);
    if ( ret == -1 && errno == EEXIST )
        printf("Microcode already up to date\n");
    else if ( ret )
    {
        fprintf(stderr, "Failed to update microcode. (err: %s)\n",
                strerror(errno));
        exit(1);
    }

    xc_interface_close(xch);

    if ( munmap(buf, len) )
    {
        printf("Could not unmap: %d(%s)\n", errno, strerror(errno));
        exit(1);
    }
    close(fd);

    return 0;
}
