#!/bin/bash

# CentOS6 preparation script.

CPWD=`pwd`

. ./common.pre.build.sh

cd ${CPWD}

LIBEVENT_MAJOR_VERSION=2
LIBEVENT_VERSION=${LIBEVENT_MAJOR_VERSION}.0.21
LIBEVENT_DISTRO=libevent-${LIBEVENT_VERSION}-stable.tar.gz
LIBEVENT_SPEC_DIR=libevent.rpm
LIBEVENT_SPEC_GIT_URL=https://github.com/coturn/coturn/raw/libevent.rpm
LIBEVENT_SPEC_FILE=libevent.spec

# Common packs

PACKS="mysql-devel sqlite sqlite-devel"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package(s) ${PACKS}"
    cd ${CPWD}
    exit -1
fi

# Libevent2:

if ! [ -f ${BUILDDIR}/SPECS/${LIBEVENT_SPEC_FILE} ] ; then 
    cd ${BUILDDIR}/tmp
    rm -rf ${LIBEVENT_SPEC_DIR}
    mkdir ${LIBEVENT_SPEC_DIR}
    cd ${LIBEVENT_SPEC_DIR}
    wget ${WGETOPTIONS} ${LIBEVENT_SPEC_GIT_URL}/${LIBEVENT_SPEC_FILE}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	cd ${CPWD}
	exit -1
    fi
    wget ${WGETOPTIONS} ${LIBEVENT_SPEC_GIT_URL}/${LIBEVENT_DISTRO}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	cd ${CPWD}
	exit -1
    fi
    cd ..
    
    if ! [ -f ${LIBEVENT_SPEC_DIR}/${LIBEVENT_SPEC_FILE} ] ; then
	echo "ERROR: cannot download ${LIBEVENT_SPEC_FILE} file"
	cd ${CPWD}
	exit -1
    fi

    cp ${LIBEVENT_SPEC_DIR}/${LIBEVENT_SPEC_FILE} ${BUILDDIR}/SPECS
    cp ${LIBEVENT_SPEC_DIR}/${LIBEVENT_DISTRO} ${BUILDDIR}/SOURCES
fi

cd ${BUILDDIR}/SPECS
rpmbuild -ba ${BUILDDIR}/SPECS/${LIBEVENT_SPEC_FILE}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    cd ${CPWD}
    exit -1
fi

PACK=${BUILDDIR}/RPMS/${ARCH}/libevent-${LIBEVENT_MAJOR_VERSION}*.rpm
sudo rpm ${RPMOPTIONS} ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACK}"
    cd ${CPWD}
    exit -1
fi

PACK=${BUILDDIR}/RPMS/${ARCH}/libevent-devel*.rpm
sudo rpm ${RPMOPTIONS} ${PACK}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACK}"
    cd ${CPWD}
    exit -1
fi

# EPEL (for hiredis)

cd ${CPWD}
./epel6.install.sh
 
# Platform file

echo "CentOS6.6" > ${BUILDDIR}/platform

cp ${CPWD}/epel6.install.sh ${BUILDDIR}/install.sh

cd ${CPWD}
