#!/bin/bash

# CentOS7 preparation script.

CPWD=`pwd`

. ./common.pre.build.sh

cd ${CPWD}

# Common packs

PACKS="libevent-devel mariadb-devel sqlite sqlite-devel"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package(s) ${PACKS}"
    cd ${CPWD}
    exit -1
fi

# EPEL (for hiredis)

cd ${CPWD}
./epel7.install.sh
 
# Platform file

echo "CentOS7.1" > ${BUILDDIR}/platform

cp ${CPWD}/epel7.install.sh ${BUILDDIR}/install.sh

cd ${CPWD}
