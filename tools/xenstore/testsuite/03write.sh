#! /bin/sh

# Write without create fails.
[ "`echo -e 'write /test none contents' | ./xs_test 2>&1`" = "FATAL: write: No such file or directory" ]

# Exclusive write succeeds
[ "`echo -e 'write /test excl contents' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'read /test' | ./xs_test 2>&1`" = "contents" ]

# Exclusive write fails to overwrite.
[ "`echo -e 'write /test excl contents' | ./xs_test 2>&1`" = "FATAL: write: File exists" ]

# Non-exclusive overwrite succeeds.
[ "`echo -e 'write /test none contents2' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'read /test' | ./xs_test 2>&1`" = "contents2" ]
[ "`echo -e 'write /test create contents3' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'read /test' | ./xs_test 2>&1`" = "contents3" ]
