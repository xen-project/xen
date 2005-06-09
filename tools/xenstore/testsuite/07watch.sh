#! /bin/sh

# Watch something, write to it, check watch has fired.
[ "`echo -e 'write /test create contents' | ./xs_test 2>&1`" = "" ]

[ "`echo -e '1 watch /test 100\n2 write /test create contents2\n1 waitwatch\n1 ackwatch' | ./xs_test 2>&1`" = "1:/test" ]

# Check that reads don't set it off.
[ "`echo -e '1 watch /test 100\n2 read /test\n1 waitwatch' | ./xs_test 2>&1`" = "2:contents2
1:waitwatch timeout" ]

# mkdir, setperm and rm should (also /tests watching dirs)
[ "`echo -e 'mkdir /dir' | ./xs_test 2>&1`" = "" ]
[ "`echo -e '1 watch /dir 100\n2 mkdir /dir/newdir\n1 waitwatch\n1 ackwatch\n2 setperm /dir/newdir 0 READ\n1 waitwatch\n1 ackwatch\n2 rm /dir/newdir\n1 waitwatch\n1 ackwatch' | ./xs_test 2>&1`" = "1:/dir/newdir
1:/dir/newdir
1:/dir/newdir" ]

# ignore watches while doing commands, should work.
[ "`echo -e 'watch /dir 100\nwrite /dir/test create contents\nread /dir/test\nwaitwatch\nackwatch' | ./xs_test 2>&1`" = "contents
/dir/test" ]

# watch priority /test.
[ "`echo -e '1 watch /dir 1\n3 watch /dir 3\n2 watch /dir 2\nwrite /dir/test create contents\n3 waitwatch\n3 ackwatch\n2 waitwatch\n2 ackwatch\n1 waitwatch\n1 ackwatch' | ./xs_test 2>&1`" = "3:/dir/test
2:/dir/test
1:/dir/test" ]

# If one dies (without acking), the other should still get ack.
[ "`echo -e '1 watch /dir 0\n2 watch /dir 1\nwrite /dir/test create contents\n2 waitwatch\n2 close\n1 waitwatch\n1 ackwatch' | ./xs_test 2>&1`" = "2:/dir/test
1:/dir/test" ]

# If one dies (without reading at all), the other should still get ack.
[ "`echo -e '1 watch /dir 0\n2 watch /dir 1\nwrite /dir/test create contents\n2 close\n1 waitwatch\n1 ackwatch' | ./xs_test 2>&1`" = "1:/dir/test" ]
