#!/bin/bash

# CentOS6 preparation script.

CPWD=`pwd`

. ./common.pre.build.sh

cd ${CPWD}

EPELRPM=epel-release-6-8.noarch.rpm
LIBEVENT_MAJOR_VERSION=2
LIBEVENT_VERSION=${LIBEVENT_MAJOR_VERSION}.0.21
LIBEVENT_DISTRO=libevent-${LIBEVENT_VERSION}-stable.tar.gz
LIBEVENT_SPEC_DIR=libevent.rpm
LIBEVENTSPEC_SVN_URL=${TURNSERVER_SVN_URL}/${LIBEVENT_SPEC_DIR}
LIBEVENT_SPEC_FILE=libevent.spec

# Common packs

PACKS="mysql-devel"
sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install package(s) ${PACKS}"
    cd ${CPWD}
    exit -1
fi

# Libevent2:

cd ${BUILDDIR}/SOURCES
if ! [ -f  ${LIBEVENT_DISTRO} ] ; then
    wget ${WGETOPTIONS} https://github.com/downloads/libevent/libevent/${LIBEVENT_DISTRO}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	cd ${CPWD}
	exit -1
    fi
fi

if ! [ -f ${BUILDDIR}/SPECS/${LIBEVENT_SPEC_FILE} ] ; then 
    cd ${BUILDDIR}/tmp
    rm -rf ${LIBEVENT_SPEC_DIR}
    svn export ${LIBEVENTSPEC_SVN_URL} ${LIBEVENT_SPEC_DIR}
    ER=$?
    if ! [ ${ER} -eq 0 ] ; then
	cd ${CPWD}
	exit -1
    fi
    
    if ! [ -f ${LIBEVENT_SPEC_DIR}/${LIBEVENT_SPEC_FILE} ] ; then
	echo "ERROR: cannot download ${LIBEVENT_SPEC_FILE} file"
	cd ${CPWD}
	exit -1
    fi

    cp ${LIBEVENT_SPEC_DIR}/${LIBEVENT_SPEC_FILE} ${BUILDDIR}/SPECS
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
./epel.install.sh
 
# Platform file

echo "CentOS6.5" > ${BUILDDIR}/platform

cp ${CPWD}/epel.install.sh ${BUILDDIR}/install.sh

cd ${CPWD}
