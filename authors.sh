#!/bin/bash

set -e

SOURCE_DIR=`pwd`

# Generate AUTHORS
echo "Thanks to the following contributors (in alphabetical order):" > ${SOURCE_DIR}/AUTHORS
echo "" >> ${SOURCE_DIR}/AUTHORS
echo "`git log --pretty=format:'- %an <%ae>' |sort|uniq`" >> ${SOURCE_DIR}/AUTHORS
echo "" >> ${SOURCE_DIR}/AUTHORS
echo "Use the following command to query the author's commit:" >> ${SOURCE_DIR}/AUTHORS
echo "   git log --author='author'" >> ${SOURCE_DIR}/AUTHORS
echo "Or see [ChangeLog](ChangeLog)" >> ${SOURCE_DIR}/AUTHORS
