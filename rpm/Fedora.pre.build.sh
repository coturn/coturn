#!/bin/bash

CPWD=`pwd`

# Fedora preparation script.

. ./common.pre.build.sh

PACKS="libevent-devel mariadb-devel sqlite sqlite-devel"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package(s) ${PACKS}"
    cd ${CPWD}
    exit -1
fi

echo "Fedora20" > ${BUILDDIR}/platform

cd ${CPWD}
