add_executable(FuzzStun FuzzStun.c)
target_link_libraries(FuzzStun turnclient ${LIB_FUZZING_ENGINE})

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
