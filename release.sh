#!/bin/bash
#! Author: Kang Lin <kl222@126.com>

set -e

SOURCE_DIR=`pwd`

if [ -n "$1" ]; then
    VERSION=`git describe --tags`
    if [ -z "$VERSION" ]; then
        VERSION=`git rev-parse HEAD`
    fi

    if [ -n "$2" ]; then
        MESSAGE=$2
    fi
    PRE_TAG=`git tag --sort=-taggerdate | head -n 1`
    echo "Current verion: $VERSION, current tag: $PRE_TAG. The version to will be set: $1 $MESSAGE"
    echo "Please check the follow list:"
    echo "    - Current is clear ?"
    echo "    - Test is ok ?"
    echo "    - Translation is ok ?"
    echo "    - Setup file is ok ?"
    
    read -t 30 -p "Be sure to input Y, not input N: " INPUT
    if [ "$INPUT" != "Y" -a "$INPUT" != "y" ]; then
        exit 0
    fi
    git tag -a $1 -m "Release $1 ${MESSAGE}"
else
    echo "usage: $0 release_version [release_message]"
    echo "   release_version format: [v][0-9].[0-9].[0-9]"
    exit -1
fi

if [ -z "${MESSAGE}" ]; then
    MESSAGE="Release $1"
else
    MESSAGE="Release $1\n${MESSAGE}"
fi

# Modify the version number in the version-related files
VERSION=`git describe --tags`
if [ -z "$VERSION" ]; then
    VERSION=`git rev-parse --short HEAD`
fi

sed -i "s/^\SET(BUILD_VERSION.*)/\SET(BUILD_VERSION \"${VERSION}\")/g" ${SOURCE_DIR}/CMakeLists.txt
sed -i "s/^\#define TURN_SERVER_VERSION.*/\#define TURN_SERVER_VERSION \"${VERSION}\"/g" ${SOURCE_DIR}/src/ns_turn_defs.h

DEBIAN_VERSION=`echo ${VERSION}|cut -d "v" -f 2`

# Generate ChangeLog
echo "$MESSAGE" >>  ${SOURCE_DIR}/ChangeLog.tmp
echo "" >> ${SOURCE_DIR}/ChangeLog.tmp
echo "Changelist:" >> ${SOURCE_DIR}/ChangeLog.tmp
echo "`git log --pretty=format:'- %s (%an <%ae>)' ${PRE_TAG}..HEAD`" >> ${SOURCE_DIR}/ChangeLog.tmp
echo "" >> ${SOURCE_DIR}/ChangeLog.tmp
echo "Contributors:" >> ${SOURCE_DIR}/ChangeLog.tmp
echo "`git log --pretty=format:'%an <%ae>' ${PRE_TAG}..HEAD|sort|uniq`" >> ${SOURCE_DIR}/ChangeLog.tmp
echo "" >> ${SOURCE_DIR}/ChangeLog.tmp

if [ -f ${SOURCE_DIR}/ChangeLog ]; then
    cat ${SOURCE_DIR}/ChangeLog >> ${SOURCE_DIR}/ChangeLog.tmp
fi
mv ${SOURCE_DIR}/ChangeLog.tmp ${SOURCE_DIR}/ChangeLog

# Generate AUTHORS
echo "Thanks to the following contributors (ranking will not be in order, in alphabetical order):" > ${SOURCE_DIR}/AUTHORS
echo "" >> ${SOURCE_DIR}/AUTHORS
echo "`git log --pretty=format:'%an <%ae>' |sort|uniq`" >> ${SOURCE_DIR}/AUTHORS
echo "" >> ${SOURCE_DIR}/AUTHORS
echo "Use the following command to query the author's commit:" >> ${SOURCE_DIR}/AUTHORS
echo "   git log --author='author'" >> ${SOURCE_DIR}/AUTHORS
echo "Or see [ChangeLog](ChangeLog)" >> ${SOURCE_DIR}/AUTHORS

git add .
git commit -m "${MESSAGE}"
git tag -d $1
git tag -a $1 -m "${MESSAGE}"
git push
git push origin $1
