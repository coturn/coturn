add_executable(FuzzStun FuzzStun.c)
target_link_libraries(FuzzStun turnclient ${LIB_FUZZING_ENGINE})

add_executable(FuzzChannelData FuzzChannelData.c)
target_link_libraries(FuzzChannelData turnclient ${LIB_FUZZING_ENGINE})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/input/FuzzChannelData_seed_corpus.zip
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/input/FuzzStun_seed_corpus.zip
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})


set(FuzzStunClientSRC
    ${CMAKE_CURRENT_SOURCE_DIR}/FuzzStunClient.c
    ${PROJECT_SOURCE_DIR}/src/apps/common/stun_buffer.c
)

add_executable(FuzzStunClient ${FuzzStunClientSRC})
target_link_libraries(FuzzStunClient turnclient ${LIB_FUZZING_ENGINE})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/input/FuzzStunClient_seed_corpus.zip
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_executable(FuzzOAuthToken FuzzOAuthToken.c)
target_link_libraries(FuzzOAuthToken turnclient ${LIB_FUZZING_ENGINE})

# --- New fuzzing targets ---

add_executable(FuzzStunAttrIter FuzzStunAttrIter.c)
target_link_libraries(FuzzStunAttrIter turnclient ${LIB_FUZZING_ENGINE})

add_executable(FuzzStunIntegrity FuzzStunIntegrity.c)
target_link_libraries(FuzzStunIntegrity turnclient ${LIB_FUZZING_ENGINE})

add_executable(FuzzStunAddrCodec FuzzStunAddrCodec.c)
target_link_libraries(FuzzStunAddrCodec turnclient ${LIB_FUZZING_ENGINE})

add_executable(FuzzOldStun FuzzOldStun.c)
target_link_libraries(FuzzOldStun turnclient ${LIB_FUZZING_ENGINE})

add_executable(FuzzOAuthRoundTrip FuzzOAuthRoundTrip.c)
target_link_libraries(FuzzOAuthRoundTrip turnclient ${LIB_FUZZING_ENGINE})

add_executable(FuzzStunAttrAdd FuzzStunAttrAdd.c)
target_link_libraries(FuzzStunAttrAdd turnclient ${LIB_FUZZING_ENGINE})

# Shared dictionary for all STUN/TURN fuzz targets
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/stun.dict
        DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
