#include "iostream.h"
#include "sys_string.h"

/** Print on a stream, like vfprintf().
 *
 * @param stream to print to
 * @param format for the print (as fprintf())
 * @param args arguments to print
 * @return result code from the print
 */
int IOStream_vprint(IOStream *stream, const char *format, va_list args){
  char buffer[1024];
  int k = sizeof(buffer), n;

  n = vsnprintf(buffer, k, (char*)format, args);
  if(n < 0 || n > k ){
      n = k;
  }
  n = IOStream_write(stream, buffer, n);
  return n;
}

/** Print on a stream, like fprintf().
 *
 * @param stream to print to
 * @param format for the print (as fprintf())
 * @return result code from the print
 */
int IOStream_print(IOStream *stream, const char *format, ...){
  va_list args;
  int result = -1;

  va_start(args, format);
  result = IOStream_vprint(stream, format, args);
  va_end(args);
  return result;
}
