#!/bin/sh

for i in `rpm -q -a | grep turnserver-utils-`
do
  echo $i
  sudo rpm -e $i
done

for i in `rpm -q -a | grep turnserver-client-libs-`
do
  echo $i
  sudo rpm -e $i
done

for i in `rpm -q -a | grep turnserver.*-`
do
  echo $i
  sudo rpm -e $i
done
