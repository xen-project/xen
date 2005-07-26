#! /bin/sh

# This demonstrates a bug where an xs_acknowledge_watch returns
# EINVAL, because the daemon doesn't track what watch event it sent
# and relies on it being the "first" watch which has an event.
# Watches firing after the first event is sent out will change this.

# Create three things to watch.
echo mkdir /test | ./xs_test
echo mkdir /test/1 | ./xs_test
echo mkdir /test/2 | ./xs_test
echo mkdir /test/3 | ./xs_test

# Watch all three, fire event on 2, read watch, fire event on 1 and 3, ack 2.
[ "`echo '1 watch /test/1 token1 0
1 watch /test/2 token2 0
1 watch /test/3 token3 0
2 write /test/2 create contents2
1 waitwatch
2 write /test/1 create contents1
2 write /test/3 create contents3
1 ackwatch token2' | ./xs_test 2>&1`" = "1:/test/2:token2" ]
