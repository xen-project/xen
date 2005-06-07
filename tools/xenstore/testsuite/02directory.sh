#! /bin/sh

# Root directory has nothing in it.
[ "`echo -e 'dir /' | ./xs_test 2>&1`" = "" ]

# Create a file.
[ "`echo -e 'write /test create contents' | ./xs_test 2>&1`" = "" ]

# Directory shows it.
[ "`echo -e 'dir /' | ./xs_test 2>&1`" = "test" ]

# Make a new directory.
[ "`echo -e 'mkdir /dir' | ./xs_test 2>&1`" = "" ]

# Check it's there.
DIR="`echo -e 'dir /' | ./xs_test 2>&1`"
[ "$DIR" = "test
dir" ] || [ "$DIR" = "dir
test" ]

# Check it's empty.
[ "`echo -e 'dir /dir' | ./xs_test 2>&1`" = "" ]

# Create a file, check it exists.
[ "`echo -e 'write /dir/test2 create contents2' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'dir /dir' | ./xs_test 2>&1`" = "test2" ]
[ "`echo -e 'read /dir/test2' | ./xs_test 2>&1`" = "contents2" ]

# Creating dir over the top should fail.
[ "`echo -e 'mkdir /dir' | ./xs_test 2>&1`" = "FATAL: mkdir: File exists" ]
[ "`echo -e 'mkdir /dir/test2' | ./xs_test 2>&1`" = "FATAL: mkdir: File exists" ]
