#!/bin/bash

# CentOS7 preparation script.

CPWD=`pwd`

. ./common.pre.build.sh

cd ${CPWD}

EPELRPM=epel-release-6-8.noarch.rpm

# Common packs

PACKS="libevent-devel mariadb-devel"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package(s) ${PACKS}"
    cd ${CPWD}
    exit -1
fi

# EPEL (for hiredis)

cd ${CPWD}
./epel.install.sh
 
# Platform file

echo "CentOS7" > ${BUILDDIR}/platform

cp ${CPWD}/epel.install.sh ${BUILDDIR}/install.sh

cd ${CPWD}
