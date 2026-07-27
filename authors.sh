#!/bin/bash

set -e

SOURCE_DIR=`pwd`

# Generate AUTHORS
echo "Thanks to the following contributors (in alphabetical order):" > ${SOURCE_DIR}/AUTHORS.md
echo "" >> ${SOURCE_DIR}/AUTHORS.md
# One entry per contributor name (first email wins), sorted case-insensitively.
# Dedupe by name so a contributor who used several email addresses is listed once.
git log --pretty=format:'%an <%ae>' | grep -v dependabot | sort -f | \
  awk -F' <' '!seen[$1]++' | sed 's/^/- /' >> ${SOURCE_DIR}/AUTHORS.md
echo "" >> ${SOURCE_DIR}/AUTHORS.md
