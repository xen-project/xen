#! /bin/sh

# Fail to get perms on non-existent file.
[ "`echo -e 'getperm /test' | ./xs_test 2>&1`" = "FATAL: getperm: No such file or directory" ]
[ "`echo -e 'getperm /dir/test' | ./xs_test 2>&1`" = "FATAL: getperm: No such file or directory" ]

# Create file: inherits from root (0 READ)
[ "`echo -e 'write /test excl contents' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'getperm /test' | ./xs_test 2>&1`" = "0 READ" ]
[ "`echo -e 'setid 1\ngetperm /test' | ./xs_test 2>&1`" = "0 READ" ]
[ "`echo -e 'setid 1\nread /test' | ./xs_test 2>&1`" = "contents" ]
[ "`echo -e 'setid 1\nwrite /test none contents2' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]

# Take away read access to file.
[ "`echo -e 'setperm /test 0 NONE' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\ngetperm /test' | ./xs_test 2>&1`" = "FATAL: getperm: Permission denied" ]
[ "`echo -e 'setid 1\nread /test' | ./xs_test 2>&1`" = "FATAL: read: Permission denied" ]
[ "`echo -e 'setid 1\nwrite /test none contents2' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]

# Grant everyone write access to file.
[ "`echo -e 'setperm /test 0 WRITE' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\ngetperm /test' | ./xs_test 2>&1`" = "FATAL: getperm: Permission denied" ]
[ "`echo -e 'setid 1\nread /test' | ./xs_test 2>&1`" = "FATAL: read: Permission denied" ]
[ "`echo -e 'setid 1\nwrite /test none contents2' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'read /test' | ./xs_test 2>&1`" = "contents2" ]

# Grant everyone both read and write access.
[ "`echo -e 'setperm /test 0 READ/WRITE' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\ngetperm /test' | ./xs_test 2>&1`" = "0 READ/WRITE" ]
[ "`echo -e 'setid 1\nread /test' | ./xs_test 2>&1`" = "contents2" ]
[ "`echo -e 'setid 1\nwrite /test none contents3' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\nread /test' | ./xs_test 2>&1`" = "contents3" ]

# Change so that user 1 owns it, noone else can do anything.
[ "`echo -e 'setperm /test 1 NONE' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\ngetperm /test' | ./xs_test 2>&1`" = "1 NONE" ]
[ "`echo -e 'setid 1\nread /test' | ./xs_test 2>&1`" = "contents3" ]
[ "`echo -e 'setid 1\nwrite /test none contents4' | ./xs_test 2>&1`" = "" ]

# User 2 can do nothing.
[ "`echo -e 'setid 2\nsetperm /test 2 NONE' | ./xs_test 2>&1`" = "FATAL: setperm: Permission denied" ]
[ "`echo -e 'setid 2\ngetperm /test' | ./xs_test 2>&1`" = "FATAL: getperm: Permission denied" ]
[ "`echo -e 'setid 2\nread /test' | ./xs_test 2>&1`" = "FATAL: read: Permission denied" ]
[ "`echo -e 'setid 2\nwrite /test none contents4' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]

# Tools can always access things.
[ "`echo -e 'getperm /test' | ./xs_test 2>&1`" = "1 NONE" ]
[ "`echo -e 'read /test' | ./xs_test 2>&1`" = "contents4" ]
[ "`echo -e 'write /test none contents5' | ./xs_test 2>&1`" = "" ]
