#!/bin/sh

for i in `rpm -q -a | grep turnserver-utils-3`
do
  echo $i
  sudo rpm -e $i
done

for i in `rpm -q -a | grep turnserver-client-libs-3`
do
  echo $i
  sudo rpm -e $i
done

for i in `rpm -q -a | grep turnserver.*-3`
do
  echo $i
  sudo rpm -e $i
done
