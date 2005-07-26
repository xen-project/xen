#! /bin/sh
# Test domain "implicit" paths.

# Create a domain, write an entry using implicit path, read using implicit
[ "`echo -e 'mkdir /home
introduce 1 100 7 /home
1 write entry1 create contents
read /home/entry1
dir /home' | ./xs_test 2>&1`" = "handle is 1
contents
entry1" ]

# Place a watch using a relative path: expect relative answer.
[ "`echo 'introduce 1 100 7 /home
1 mkdir foo
1 watch foo token
async write /home/foo/bar create contents
1 waitwatch
1 ackwatch token' | ./xs_test 2>&1`" = "handle is 1
1:foo/bar:token" ]
