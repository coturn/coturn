set(FUZZ_COMMON_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/FuzzOpenSSLInit.c
)

# Only two fuzz targets are produced because the upstream OSS-Fuzz build
# recipe (google/oss-fuzz/projects/coturn/build.sh) copies only these two
# binaries and their seed corpora into $OUT. Additional fuzzing coverage is
# reached by dispatching from a single-byte selector inside each target.

add_executable(FuzzStun FuzzStun.c ${FUZZ_COMMON_SOURCES})
target_link_libraries(FuzzStun turnclient ${LIB_FUZZING_ENGINE})

set(FuzzStunClientSRC
    ${CMAKE_CURRENT_SOURCE_DIR}/FuzzStunClient.c
    ${PROJECT_SOURCE_DIR}/src/apps/common/stun_buffer.c
)

add_executable(FuzzStunClient ${FuzzStunClientSRC} ${FUZZ_COMMON_SOURCES})
target_link_libraries(FuzzStunClient turnclient ${LIB_FUZZING_ENGINE})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/input/FuzzStun_seed_corpus.zip
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/input/FuzzStunClient_seed_corpus.zip
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# Shared dictionary for STUN/TURN fuzz targets
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/stun.dict
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
