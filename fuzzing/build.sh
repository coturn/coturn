#!/bin/bash -eu

build(){
   export CFLAGS="$1"
   export CXXFLAGS="$1"
   export LIB_FUZZING_ENGINE=-fsanitize=fuzzer

   mkdir build && cd build/
   cmake -DFUZZER=ON -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" ../../.
   make -j$(nproc)

   cd fuzzing/
   unzip FuzzStun_seed_corpus.zip
   unzip FuzzStunClient_seed_corpus.zip

   mkdir FuzzStun_Corpus
   mkdir FuzzStunClient_Corpus
}

run(){
   DIR=build/fuzzing
   if [ $1 == '0' ]
   then
      ./$DIR/FuzzStun   $DIR/FuzzStun_Corpus/   $DIR/FuzzStun_seed_corpus
   else
      ./$DIR/FuzzStunClient   $DIR/FuzzStunClient_Corpus/   $DIR/FuzzStunClient_seed_corpus
   fi   
}

help(){
   echo "use: ./$0 ASan | UBSan | MSan | Run 0 | Run 1"
}

if [ -z "$1" ]
then
   help
elif [ $1 == "ASan" ]
then
   build "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
elif [ "$1" == "UBSan" ]
then
   build "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fsanitize=fuzzer-no-link"
elif [ "$1" == "MSan" ]
then
   build "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=memory -fsanitize-memory-track-origins -fsanitize=fuzzer-no-link"
elif [ "$1" == "Run" ]
then
   run $2
else
  help
fi
