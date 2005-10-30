#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <xenctrl.h>

int main(int argc, char * argv[])
{
    int enable;
    int xc_handle = xc_interface_open();
    
    if (argc < 2) {
      printf("usage: %s [0|1]\n", argv[0]);
      exit(1);
    }
    enable = atoi(argv[1]);

    if (xc_tbuf_enable(xc_handle, enable) != 0) {
        perror("Enable/Disable Hypercall failure");
        exit(1);
    }
    else
      printf("Tracing now %s\n", (enable ? "enabled" : "disabled"));

    xc_interface_close(xc_handle);
    return 0;
}
