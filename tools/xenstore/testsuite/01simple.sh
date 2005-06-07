#! /bin/sh

# Create an entry, read it.
[ "`echo -e 'write /test create contents\nread /test' | ./xs_test 2>&1`" = "contents" ]
