#! /bin/sh

# Remove non-existant fails.
[ "`echo -e 'rm /test' | ./xs_test 2>&1`" = "FATAL: rm: No such file or directory" ]
[ "`echo -e 'rm /dir/test' | ./xs_test 2>&1`" = "FATAL: rm: No such file or directory" ]

# Create file and remove it
[ "`echo -e 'write /test excl contents' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'rm /test' | ./xs_test 2>&1`" = "" ]

# Create directory and remove it.
[ "`echo -e 'mkdir /dir' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'rm /dir' | ./xs_test 2>&1`" = "" ]

# Create directory, create file, remove all.
[ "`echo -e 'mkdir /dir' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'write /dir/test excl contents' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'rm /dir' | ./xs_test 2>&1`" = "" ]
