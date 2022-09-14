#####
How-to Guide for fuzzing in localhost.


- Export flags.

####
LibFuzzer with AddressSanitizer

```
export CC=clang
export CXX=clang++
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
export CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -stdlib=libc++"
export RUSTFLAGS="--cfg fuzzing -Cdebuginfo=1 -Cforce-frame-pointers -Zinstrument-coverage -C link-arg=-lc++"
export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
```

####
LibFuzzer with UndefinedBehaviorSanitizer

```
export CC=clang
export CXX=clang++
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fsanitize=fuzzer-no-link"
export CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fsanitize=fuzzer-no-link -stdlib=libc++"
export RUSTFLAGS="--cfg fuzzing -Cdebuginfo=1 -Cforce-frame-pointers"
export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
```

####
LibFuzzer with UndefinedBehaviorSanitizer

```
CC=clang
CXX=clang++
CFLAGS=-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=memory -fsanitize-memory-track-origins -fsanitize=fuzzer-no-link
CXXFLAGS=-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=memory -fsanitize-memory-track-origins -fsanitize=fuzzer-no-link -stdlib=libc++
RUSTFLAGS=--cfg fuzzing -Zsanitizer=memory -Cdebuginfo=1 -Cforce-frame-pointers
export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
```

- Compile Everything.
```
cd coturn/fuzzing/
make
```

- Run the Fuzzer.
```
cd input/
unzip FuzzStun_seed_corpus.zip
unzip FuzzStunClient_seed_corpus.zip

cd ../
mkdir FuzzStun_Corpus
mkdir FuzzStunClient_Corpus

./FuzzStun FuzzStun_Corpus/ input/FuzzStun_seed_corpus
./FuzzStunClient FuzzStunClient_Corpus/ input/FuzzStunClient_seed_corpus

```
