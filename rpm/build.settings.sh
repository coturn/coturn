#!/bin/bash

# Common settings script.

TURNVERSION=4.5.1.0
BUILDDIR=~/rpmbuild
ARCH=`uname -p`
TURNSERVER_GIT_URL=https://github.com/coturn/coturn.git

WGETOPTIONS="--no-check-certificate"
RPMOPTIONS="-ivh --force"


