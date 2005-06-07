#! /bin/sh

# Root directory: owned by tool, everyone has read access.
[ "`echo -e 'getperm /' | ./xs_test 2>&1`" = "0 READ" ]

# Create directory: we own it, noone has access.
[ "`echo -e 'mkdir /dir' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'getperm /dir' | ./xs_test 2>&1`" = "0 NONE" ]
[ "`echo -e 'setid 1\ndir /dir' | ./xs_test 2>&1`" = "FATAL: dir: Permission denied" ]
[ "`echo -e 'setid 1\nread /dir/test create contents2' | ./xs_test 2>&1`" = "FATAL: read: Permission denied" ]
[ "`echo -e 'setid 1\nwrite /dir/test create contents2' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]

# Grant everyone read access to directoy.
[ "`echo -e 'setperm /dir 0 READ' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\ngetperm /dir' | ./xs_test 2>&1`" = "0 READ" ]
[ "`echo -e 'setid 1\ndir /dir' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\nwrite /dir/test create contents2' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]

# Grant everyone write access to directory.
[ "`echo -e 'setperm /dir 0 WRITE' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\ngetperm /dir' | ./xs_test 2>&1`" = "FATAL: getperm: Permission denied" ]
[ "`echo -e 'setid 1\ndir /dir' | ./xs_test 2>&1`" = "FATAL: dir: Permission denied" ]
[ "`echo -e 'setid 1\nwrite /dir/test create contents' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'read /dir/test' | ./xs_test 2>&1`" = "contents" ]

# Grant everyone both read and write access.
[ "`echo -e 'setperm /dir 0 READ/WRITE' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\ngetperm /dir' | ./xs_test 2>&1`" = "0 READ/WRITE" ]
[ "`echo -e 'setid 1\ndir /dir' | ./xs_test 2>&1`" = "test" ]
[ "`echo -e 'setid 1\nwrite /dir/test2 create contents' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\nread /dir/test2' | ./xs_test 2>&1`" = "contents" ]

# Change so that user 1 owns it, noone else can do anything.
[ "`echo -e 'setperm /dir 1 NONE' | ./xs_test 2>&1`" = "" ]
[ "`echo -e 'setid 1\ngetperm /dir' | ./xs_test 2>&1`" = "1 NONE" ]
[ "`echo -e 'setid 1\ndir /dir' | ./xs_test 2>&1 | sort`" = "test
test2" ]
[ "`echo -e 'setid 1\nwrite /dir/test3 create contents' | ./xs_test 2>&1`" = "" ]

# User 2 can do nothing.  Can't even tell if file exists.
[ "`echo -e 'setid 2\nsetperm /dir 2 NONE' | ./xs_test 2>&1`" = "FATAL: setperm: Permission denied" ]
[ "`echo -e 'setid 2\ngetperm /dir' | ./xs_test 2>&1`" = "FATAL: getperm: Permission denied" ]
[ "`echo -e 'setid 2\ndir /dir' | ./xs_test 2>&1`" = "FATAL: dir: Permission denied" ]
[ "`echo -e 'setid 2\nread /dir/test' | ./xs_test 2>&1`" = "FATAL: read: Permission denied" ]
[ "`echo -e 'setid 2\nread /dir/test2' | ./xs_test 2>&1`" = "FATAL: read: Permission denied" ]
[ "`echo -e 'setid 2\nread /dir/test3' | ./xs_test 2>&1`" = "FATAL: read: Permission denied" ]
[ "`echo -e 'setid 2\nread /dir/test4' | ./xs_test 2>&1`" = "FATAL: read: Permission denied" ]
[ "`echo -e 'setid 2\nwrite /dir/test none contents' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]
[ "`echo -e 'setid 2\nwrite /dir/test create contents' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]
[ "`echo -e 'setid 2\nwrite /dir/test excl contents' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]
[ "`echo -e 'setid 2\nwrite /dir/test4 none contents' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]
[ "`echo -e 'setid 2\nwrite /dir/test4 create contents' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]
[ "`echo -e 'setid 2\nwrite /dir/test4 excl contents' | ./xs_test 2>&1`" = "FATAL: write: Permission denied" ]

# Tools can always access things.
[ "`echo -e 'getperm /dir' | ./xs_test 2>&1`" = "1 NONE" ]
[ "`echo -e 'dir /dir' | ./xs_test 2>&1 | sort`" = "test
test2
test3" ]
[ "`echo -e 'write /dir/test4 create contents' | ./xs_test 2>&1`" = "" ]

