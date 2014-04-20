#!/bin/sh
#
# This is a script for RFC 5769 STUN protocol check.
# It checks whether the main code was compiled correctly.
#

if [ -d examples ] ; then
       cd examples
fi

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/
export DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}:/usr/local/lib/

PATH=examples/bin/:bin/:../bin:${PATH} turnutils_rfc5769check $@
