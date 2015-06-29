#!/bin/bash

# Common settings script.

TURNVERSION=4.4.5.3
BUILDDIR=~/rpmbuild
ARCH=`uname -p`
TURNSERVER_SVN_URL=http://coturn.googlecode.com/svn
TURNSERVER_SVN_URL_VER=trunk

WGETOPTIONS="--no-check-certificate"
RPMOPTIONS="-ivh --force"


