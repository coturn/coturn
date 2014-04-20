#!/bin/sh
#
# This is an example of a script to run a DOS attack in a 
# "secure" environment
#

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

while [ 0 ] ; do 

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -G -O -n 10 -m 10 -l 170 -g -u ninefingers -w youhavetoberealistic -y $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -G -O -n 10 -m 10 -l 170 -e 127.0.0.1 -X -g -u ninefingers -w youhavetoberealistic $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -G -O -S -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e ::1 -x -g -u ninefingers -w youhavetoberealistic -s $@ 127.0.0.1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -G -O -t -n 30 -m 10 -l 170 -e 127.0.0.1 -X -g -u gorst -w hero $@ ::1 &

PATH=examples/bin/:../bin/:./bin/:${PATH} turnutils_uclient -G -O -T -n 10 -m 10 -l 170 -y -g -u gorst -w hero $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -G -O -T -S -k turn_client_pkey.pem -n 10 -m 10 -l 170 -y -g -u gorst -w hero $@ ::1 &

PATH=examples/bin/:../bin:./bin/:${PATH} turnutils_uclient -G -O -t -S -k turn_client_pkey.pem -n 10 -m 10 -l 170 -e 127.0.0.1 -X -g -u gorst -w hero $@ ::1 &

sleep 2

type killall >>/dev/null 2>>/dev/null
ER=$?
if [ ${ER} -eq 0 ] ; then
  killall turnutils_uclient >>/dev/null 2>>/dev/null
fi

type pkill >>/dev/null 2>>/dev/null
ER=$?
if [ ${ER} -eq 0 ] ; then
  pkill turnutils_u >>/dev/null 2>>/dev/null
  pkill turnutils_uclie >>/dev/null 2>>/dev/null
  pkill turnutils_uclient >>/dev/null 2>>/dev/null
else
  sleep 10
fi

done


