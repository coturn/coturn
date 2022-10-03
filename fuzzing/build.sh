#!/bin/bash -eu

ASan() {
   echo "Using AddressSanitizer"
   export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
   export CXXFLAGS="$CFLAGS"
   export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
}

UBSan() {
   echo "Using UndefinedBehaviorSanitizer"
   export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fsanitize=fuzzer-no-link"
   export CXXFLAGS="$CFLAGS"
   export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
}

MSan() {
   echo "Using MemorySanitizer"
   export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=memory -fsanitize-memory-track-origins -fsanitize=fuzzer-no-link"
   export CXXFLAGS="$CFLAGS"
   export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
}

if [ $1 == "ASan" ]
then
  ASan
elif [ "$1" == "UBSan" ]
then
  UBSan
elif [ "$1" == "MSan" ]
then
  MSan
else
  echo "use: $0 ASan | UBSan | MSan"
fi
