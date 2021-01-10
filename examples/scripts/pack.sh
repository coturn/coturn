#!/bin/sh

# Run it from the root of the coturn source tree

V=4.5.2

PACKDIR=`pwd`/../coturn-releases/
SRCDIR=`pwd`
DDIR=turnserver-${V}

cd ${SRCDIR}/
make distclean
cd ${PACKDIR}
rm -rf tmp
mkdir tmp
cd tmp
mkdir ${DDIR}
cp -R ${SRCDIR}/* ${DDIR}/
#tell tar to not include the metadata
COPYFILE_DISABLE=1 tar cvfz ../${DDIR}.tar.gz ${DDIR}
cd ..
rm -rf tmp

cp -a ${SRCDIR}/ChangeLog ${PACKDIR}
