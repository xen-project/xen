#! /bin/sh
# Test transactions.

# Simple transaction: create a file inside transaction.
[ "`echo -e '1 start /
1 write /entry1 create contents
2 dir /
1 dir /
1 commit
2 read /entry1' | ./xs_test`" = "1:entry1
2:contents" ]
echo rm /entry1 | ./xs_test

# Create a file and abort transaction.
[ "`echo -e '1 start /
1 write /entry1 create contents
2 dir /
1 dir /
1 abort
2 dir /' | ./xs_test`" = "1:entry1" ]

echo write /entry1 create contents | ./xs_test
# Delete in transaction, commit
[ "`echo -e '1 start /
1 rm /entry1
2 dir /
1 dir /
1 commit
2 dir /' | ./xs_test`" = "2:entry1" ]

# Delete in transaction, abort.
echo write /entry1 create contents | ./xs_test
[ "`echo -e '1 start /
1 rm /entry1
2 dir /
1 dir /
1 abort
2 dir /' | ./xs_test`" = "2:entry1
2:entry1" ]

# Transactions can take as long as the want...
[ "`echo -e 'start /
sleep 1
rm /entry1
commit
dir /' | ./xs_test`" = "" ]

# ... as long as noone is waiting.
[ "`echo -e '1 start /
2 mkdir /dir
1 mkdir /dir
1 dir /
1 commit' | ./xs_test 2>&1`" = "1:dir
FATAL: 1: commit: Connection timed out" ]
