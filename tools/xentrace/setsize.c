#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <xenctrl.h>

int main(int argc, char * argv[])
{
    unsigned long size;
    xc_interface *xc_handle = xc_interface_open(0,0,0);
  
    if ( xc_tbuf_get_size(xc_handle, &size) != 0 )
    {
        perror("Failure to get tbuf info from Xen. Guess size is 0");
        printf("This may mean that tracing is not enabled in xen.\n");
    }
    else
    {
        printf("Current tbuf size: 0x%lx\n", size);
    }

    if (argc < 2)
        exit(0);

    size = atol(argv[1]);

    if ( xc_tbuf_set_size(xc_handle, size) != 0 )
    {
        perror("set_size Hypercall failure");
        exit(1);
    }
    printf("set_size succeeded.\n");
  
    if (xc_tbuf_get_size(xc_handle, &size) != 0)
        perror("Failure to get tbuf info from Xen."
               " Tracing must be enabled first");
    else
        printf("New tbuf size: 0x%lx\n", size);
  
    xc_interface_close(xc_handle);
    return 0;
}
