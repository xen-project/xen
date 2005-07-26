#! /bin/sh

# Watch something, write to it, check watch has fired.
[ "`echo -e 'write /test create contents' | ./xs_test 2>&1`" = "" ]

[ "`echo -e '1 watch /test token
2 async write /test create contents2
1 waitwatch
1 ackwatch token' | ./xs_test 2>&1`" = "1:/test:token" ]

# Check that reads don't set it off.
[ "`echo -e '1 watch /test token
2 read /test
1 waitwatch' | ./xs_test 2>&1`" = "2:contents2
1:waitwatch timeout" ]

# mkdir, setperm and rm should (also tests watching dirs)
[ "`echo -e 'mkdir /dir' | ./xs_test 2>&1`" = "" ]
[ "`echo -e '1 watch /dir token
2 async mkdir /dir/newdir
1 waitwatch
1 ackwatch token
asyncwait
2 async setperm /dir/newdir 0 READ
1 waitwatch
1 ackwatch token
asyncwait
2 async rm /dir/newdir
1 waitwatch
1 ackwatch token' | ./xs_test 2>&1`" = "1:/dir/newdir:token
1:/dir/newdir:token
1:/dir/newdir:token" ]

# We don't get a watch from our own commands.
[ "`echo -e 'watch /dir token
mkdir /dir/newdir
waitwatch' | ./xs_test 2>&1`" = "waitwatch timeout" ]

# ignore watches while doing commands, should work.
[ "`echo -e 'watch /dir token
1 async write /dir/test create contents
read /dir/test
waitwatch
ackwatch token' | ./xs_test 2>&1`" = "contents
/dir/test:token" ]

# watch priority test: all simultaneous
[ "`echo -e '1 watch /dir token1
3 watch /dir token3
2 watch /dir token2
async write /dir/test create contents
3 waitwatch
3 ackwatch token3
2 waitwatch
2 ackwatch token2
1 waitwatch
1 ackwatch token1' | ./xs_test 2>&1`" = "3:/dir/test:token3
2:/dir/test:token2
1:/dir/test:token1" ]

# If one dies (without acking), the other should still get ack.
[ "`echo -e '1 watch /dir token1
2 watch /dir token2
async write /dir/test create contents
2 waitwatch
2 close
1 waitwatch
1 ackwatch token1' | ./xs_test 2>&1`" = "2:/dir/test:token2
1:/dir/test:token1" ]

# If one dies (without reading at all), the other should still get ack.
[ "`echo -e '1 watch /dir token1
2 watch /dir token2
async write /dir/test create contents
2 close
1 waitwatch
1 ackwatch token1' | ./xs_test 2>&1`" = "1:/dir/test:token1" ]

# unwatch
[ "`echo -e '1 watch /dir token1
1 unwatch /dir token1
1 watch /dir token2
2 async write /dir/test2 create contents
1 waitwatch
1 unwatch /dir token2' | ./xs_test 2>&1`" = "1:/dir/test2:token2" ]

# unwatch while watch pending.  Next watcher gets the event.
[ "`echo -e '1 watch /dir token1
2 watch /dir token2
async write /dir/test create contents
2 unwatch /dir token2
1 waitwatch
1 ackwatch token1' | ./xs_test 2>&1`" = "1:/dir/test:token1" ]

# unwatch while watch pending.  Should clear this so we get next event.
[ "`echo -e '1 watch /dir token1
async write /dir/test create contents
1 unwatch /dir token1
1 watch /dir/test token2
asyncwait
async write /dir/test none contents2
1 waitwatch
1 ackwatch token2' | ./xs_test 2>&1`" = "1:/dir/test:token2" ]

# check we only get notified once.
[ "`echo -e '1 watch /test token
2 async write /test create contents2
1 waitwatch
1 ackwatch token
1 waitwatch' | ./xs_test 2>&1`" = "1:/test:token
1:waitwatch timeout" ]

# watches are queued in order.
[ "`echo -e '1 watch / token
async 2 write /test1 create contents
async 2 write /test2 create contents
async 2 write /test3 create contents
1 waitwatch
1 ackwatch token
1 waitwatch
1 ackwatch token
1 waitwatch
1 ackwatch token' | ./xs_test 2>&1`" = "1:/test1:token
1:/test2:token
1:/test3:token" ]

# Creation of subpaths should be covered correctly.
[ "`echo -e '1 watch / token
2 async write /test/subnode create contents2
2 async write /test/subnode/subnode create contents2
1 waitwatch
1 ackwatch token
1 waitwatch
1 ackwatch token
1 waitwatch' | ./xs_test 2>&1`" = "1:/test/subnode:token
1:/test/subnode/subnode:token
1:waitwatch timeout" ]

# Watch event must have happened before we registered interest.
[ "`echo -e '1 watch / token
2 async write /test/subnode create contents2
1 watch / token2 0
1 waitwatch
1 ackwatch token
1 waitwatch' | ./xs_test 2>&1`" = "1:/test/subnode:token
1:waitwatch timeout" ]

# Rm fires notification on child.
[ "`echo -e '1 watch /test/subnode token
2 async rm /test
1 waitwatch
1 ackwatch token' | ./xs_test 2>&1`" = "1:/test/subnode:token" ]

# Watch should not double-send after we ack, even if we did something in between.
[ "`echo -e '1 watch /test2 token
2 async write /test2/foo create contents2
1 waitwatch
1 read /test2/foo
1 ackwatch token
1 waitwatch' | ./xs_test 2>&1`" = "1:/test2/foo:token
1:contents2
1:waitwatch timeout" ]
