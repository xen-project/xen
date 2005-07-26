#! /bin/sh
# Test domain communication.

# Create a domain, write an entry.
[ "`echo -e 'introduce 1 100 7 /my/home
1 write /entry1 create contents
dir /' | ./xs_test 2>&1 | sort`" = "entry1
handle is 1
tool" ]

# Release that domain.
[ "`echo -e 'release 1' | ./xs_test`" = "" ]

# Introduce and release by same connection.
[ "`echo -e 'introduce 1 100 7 /my/home
release 1' | ./xs_test 2>&1`" = "handle is 1" ]
