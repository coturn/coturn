#!/bin/bash

CPWD=`pwd`

. ./build.settings.sh

# Required packages

PACKS="postgresql-devel hiredis-devel"

sudo yum -y install ${PACKS}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    echo "Cannot install packages ${PACKS}"
    cd ${CPWD}
    exit -1
fi

# TURN

cd ${BUILDDIR}/tmp
rm -rf turnserver-${TURNVERSION}
git clone ${TURNSERVER_GIT_URL} --branch ${TURNVERSION} turnserver-${TURNVERSION}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    cd ${CPWD}
    exit -1
fi

tar zcf ${BUILDDIR}/SOURCES/turnserver-${TURNVERSION}.tar.gz turnserver-${TURNVERSION}
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    cd ${CPWD}
    exit -1
fi

rpmbuild -ta ${BUILDDIR}/SOURCES/turnserver-${TURNVERSION}.tar.gz
ER=$?
if ! [ ${ER} -eq 0 ] ; then
    cd ${CPWD}
    exit -1
fi

# Make binary tarball

cd ${BUILDDIR}/RPMS/${ARCH}
mkdir -p di
mv *debuginfo* di
mv *devel* di
rm -rf turnserver-${TURNVERSION}
mkdir turnserver-${TURNVERSION}
mv *.rpm turnserver-${TURNVERSION}/

rm -rf turnserver-${TURNVERSION}/install.sh

if [ -f ${BUILDDIR}/install.sh ] ; then
    cat ${BUILDDIR}/install.sh > turnserver-${TURNVERSION}/install.sh
else
    echo "#!/bin/sh" > turnserver-${TURNVERSION}/install.sh
fi

cat <<EOF >>turnserver-${TURNVERSION}/install.sh

sudo yum -y install openssl
sudo yum -y install telnet
sudo yum -y install sqlite
  
for i in *.rpm ; do

  sudo yum -y install \${i}
  ER=\$?
  if ! [ \${ER} -eq 0 ] ; then
    sudo rpm -Uvh \${i}
    ER=\$?
    if ! [ \${ER} -eq 0 ] ; then
      sudo rpm -ivh --force \${i}
      ER=\$?
      if ! [ \${ER} -eq 0 ] ; then
        echo "ERROR: cannot install package \${i}"
        exit -1
      fi
    fi
  fi
done

echo SUCCESS !

EOF

chmod a+x turnserver-${TURNVERSION}/install.sh

cp ${CPWD}/uninstall.turnserver.sh turnserver-${TURNVERSION}/
chmod a+x turnserver-${TURNVERSION}/uninstall.turnserver.sh

PLATFORM=`cat ${BUILDDIR}/platform`

tar cvfz turnserver-${TURNVERSION}-${PLATFORM}-${ARCH}.tar.gz turnserver-${TURNVERSION}

cd ${CPWD}
