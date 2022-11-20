#!/bin/bash
#! Author: Kang Lin <kl222@126.com>

set -e

SOURCE_DIR=`pwd`

if [ -n "$1" ]; then
    VERSION=$1

    if [ -n "$2" ]; then
        MESSAGE=$2
    fi
    PRE_TAG=`git tag --sort=-creatordate | grep -v -E "upstream|docker|debian" | head -n 1`
    echo "Current version: $PRE_TAG. The version to will be set: $1 $MESSAGE"
else
    echo "usage: $0 release_version [release_message]"
    echo "   release_version format: [v][0-9].[0-9].[0-9]"
    exit -1
fi

if [ -z "${MESSAGE}" ]; then
    MESSAGE="Release $1"
else
    MESSAGE="Release $1: ${MESSAGE}"
fi

VERSION=$1

sed -i "s/SET(BUILD_VERSION \".*)/SET(BUILD_VERSION \"${VERSION}\")/g" ${SOURCE_DIR}/CMakeLists.txt
sed -i "s/#define TURN_SERVER_VERSION .*/#define TURN_SERVER_VERSION \"${VERSION}\"/g" ${SOURCE_DIR}/src/ns_turn_defs.h

# Generate ChangeLog
if [ -f ${SOURCE_DIR}/ChangeLog ]; then
    mv ${SOURCE_DIR}/ChangeLog ${SOURCE_DIR}/ChangeLog.tmp
fi

echo "$MESSAGE" >  ${SOURCE_DIR}/ChangeLog
echo "" >> ${SOURCE_DIR}/ChangeLog
echo "Changelist:" >> ${SOURCE_DIR}/ChangeLog
echo "`git log --pretty=format:'- %s (%an <%ae>)' ${PRE_TAG}..HEAD | grep -v dependabot`" >> ${SOURCE_DIR}/ChangeLog
echo "" >> ${SOURCE_DIR}/ChangeLog
echo "Contributors:" >> ${SOURCE_DIR}/ChangeLog
echo "`git log --pretty=format:'- %an <%ae>' ${PRE_TAG}..HEAD|sort|uniq`" >> ${SOURCE_DIR}/ChangeLog
echo "" >> ${SOURCE_DIR}/ChangeLog

cat ${SOURCE_DIR}/ChangeLog.tmp >> ${SOURCE_DIR}/ChangeLog
rm ${SOURCE_DIR}/ChangeLog.tmp
