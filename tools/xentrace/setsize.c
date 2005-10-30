#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <xenctrl.h>

int main(int argc, char * argv[])
{
  unsigned int size;
  int xc_handle = xc_interface_open();
  
  if (xc_tbuf_get_size(xc_handle, &size) != 0) {
    perror("Failure to get tbuf info from Xen. Guess size is 0.");
    printf("This may mean that tracing is not compiled into xen.\n");
    exit(1);
  }
  else
    printf("Current tbuf size: 0x%x\n", size);
  
  if (argc < 2)
    exit(0);

  size = atoi(argv[1]);

  if (xc_tbuf_set_size(xc_handle, size) != 0) {
    perror("set_size Hypercall failure");
    exit(1);
  }
  
  if (xc_tbuf_get_size(xc_handle, &size) != 0)
    perror("Failure to get tbuf info from Xen. Guess size is 0.");
  else
    printf("New tbuf size: 0x%x\n", size);
  
  xc_interface_close(xc_handle);
  return 0;
}
