#! /bin/sh
# Test transactions.

echo mkdir /test | ./xs_test

# Simple transaction: create a file inside transaction.
[ "`echo -e '1 start /test
1 write /test/entry1 create contents
2 dir /test
1 dir /test
1 commit
2 read /test/entry1' | ./xs_test`" = "1:entry1
2:contents" ]
echo rm /test/entry1 | ./xs_test

# Create a file and abort transaction.
[ "`echo -e '1 start /test
1 write /test/entry1 create contents
2 dir /test
1 dir /test
1 abort
2 dir /test' | ./xs_test`" = "1:entry1" ]

echo write /test/entry1 create contents | ./xs_test
# Delete in transaction, commit
[ "`echo -e '1 start /test
1 rm /test/entry1
2 dir /test
1 dir /test
1 commit
2 dir /test' | ./xs_test`" = "2:entry1" ]

# Delete in transaction, abort.
echo write /test/entry1 create contents | ./xs_test
[ "`echo -e '1 start /test
1 rm /test/entry1
2 dir /test
1 dir /test
1 abort
2 dir /test' | ./xs_test`" = "2:entry1
2:entry1" ]

# Transactions can take as long as the want...
[ "`echo -e 'start /test
sleep 1
rm /test/entry1
commit
dir /test' | ./xs_test`" = "" ]

# ... as long as noone is waiting.
[ "`echo -e '1 start /test
2 mkdir /test/dir
1 mkdir /test/dir
1 dir /test
1 commit' | ./xs_test 2>&1`" = "1:dir
FATAL: 1: commit: Connection timed out" ]

# Events inside transactions don't trigger watches until (successful) commit.
[ "`echo -e '1 watch /test token 100
2 start /test
2 mkdir /test/dir/sub
1 waitwatch' | ./xs_test 2>&1`" = "1:waitwatch timeout" ]
[ "`echo -e '1 watch /test token 100
2 start /test
2 mkdir /test/dir/sub
2 abort
1 waitwatch' | ./xs_test 2>&1`" = "1:waitwatch timeout" ]
[ "`echo -e '1 watch /test token 100
2 start /test
2 mkdir /test/dir/sub
2 commit
1 waitwatch
1 ackwatch token' | ./xs_test 2>&1`" = "1:/test/dir/sub:token" ]

# Rm inside transaction works like rm outside: children get notified.
[ "`echo -e '1 watch /test/dir/sub token 100
2 start /test
2 rm /test/dir
2 commit
1 waitwatch
1 ackwatch token' | ./xs_test 2>&1`" = "1:/test/dir/sub:token" ]
