#!/bin/bash

# Common settings script.

TURNVERSION=4.7.0
BUILDDIR=~/rpmbuild
ARCH=`uname -p`

WGETOPTIONS="--no-check-certificate"
RPMOPTIONS="-ivh --force"


