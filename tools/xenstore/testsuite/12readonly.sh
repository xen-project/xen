#! /bin/sh
# Test that read only connection can't alter store.

[ "`echo 'write /test create contents' | ./xs_test 2>&1`" = "" ]

# These are all valid.
[ "`echo dir / | ./xs_test --readonly 2>&1 | sort`" = "test
tool" ]

[ "`echo 'read /test
getperm /test
watch /test token 0
unwatch /test token 
start /
commit
start /
abort' | ./xs_test --readonly 2>&1`" = "contents
0 READ" ]

# These don't work
[ "`echo 'write /test2 create contents' | ./xs_test --readonly 2>&1`" = "FATAL: write: Read-only file system" ]
[ "`echo 'write /test create contents' | ./xs_test --readonly 2>&1`" = "FATAL: write: Read-only file system" ]
[ "`echo 'setperm /test 100 NONE' | ./xs_test --readonly 2>&1`" = "FATAL: setperm: Read-only file system" ]
[ "`echo 'setperm /test 100 NONE' | ./xs_test --readonly 2>&1`" = "FATAL: setperm: Read-only file system" ]
[ "`echo 'shutdown' | ./xs_test --readonly 2>&1`" = "FATAL: shutdown: Read-only file system" ]
[ "`echo 'introduce 1 100 7 /home' | ./xs_test --readonly 2>&1`" = "FATAL: introduce: Read-only file system" ]

# Check that watches work like normal.
set -m
[ "`echo 'watch / token 0
waitwatch
ackwatch token' | ./xs_test --readonly 2>&1`" = "/test:token" ] &

[ "`echo 'write /test create contents' | ./xs_test 2>&1`" = "" ]
if wait; then :; else
    echo Readonly wait test failed: $?
    exit 1
fi
    
    

