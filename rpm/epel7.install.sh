#!/bin/bash

CPWD=`pwd`

# Epel installation script

EPEL=epel-release-7-5.noarch
EPELRPM=${EPEL}.rpm
BUILDDIR=~/rpmbuild
WGETOPTIONS="--no-check-certificate"
RPMOPTIONS="-ivh --force"

mkdir -p ${BUILDDIR}
mkdir -p ${BUILDDIR}/RPMS

sudo yum -y install wget

cd ${BUILDDIR}/RPMS
if ! [ -f ${EPELRPM} ] ; then
    wget ${WGETOPTIONS} http://download.fedoraproject.org/pub/epel/7/x86_64/e/${EPELRPM}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	cd ${CPWD}
	exit -1
    fi
fi

PACK=${EPELRPM}
sudo rpm ${RPMOPTIONS} ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package ${PACK}"
    cd ${CPWD}
    exit -1
fi

cd ${CPWD}


