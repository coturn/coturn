#!/bin/sh
#
# This is an example of a script for DOS attack emulation

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/

while [ 0 ] ; do

PATH=examples/bin/:../bin/:bin/:${PATH} turnutils_uclient -O -D -G -n 1 -m 12 -e 127.0.0.1 -X -g $@ ::1 &

PATH=examples/bin/:../bin/:bin/:${PATH} turnutils_uclient -O -G -n 1 -m 12 -y -s $@ 127.0.0.1 &

PATH=examples/bin/:../bin:bin/:${PATH} turnutils_uclient -O -G -t -n 1 -m 12 -e 127.0.0.1 -X -g $@ ::1 &

PATH=examples/bin/:../bin:bin/:${PATH} turnutils_uclient -O -G -T -n 1 -m 12 -y -s $@ 127.0.0.1 &

sleep 1

type killall >>/dev/null 2>>/dev/null
ER=$?
if [ ${ER} -eq 0 ] ; then
  killall turnutils_uclient >>/dev/null 2>>/dev/null
else
  type pkill >>/dev/null 2>>/dev/null
  ER=$?
  if [ ${ER} -eq 0 ] ; then
    pkill turnutils_u >>/dev/null 2>>/dev/null
  fi
fi

done
