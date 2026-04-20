include(FetchContent)

FetchContent_Declare(
    Unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG        v2.6.0
)
FetchContent_MakeAvailable(Unity)

function(coturn_add_test name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE turnclient unity)
    add_test(NAME ${name} COMMAND ${name})
    list(APPEND COTURN_TEST_TARGETS ${name})
    set(COTURN_TEST_TARGETS ${COTURN_TEST_TARGETS} PARENT_SCOPE)
endfunction()

coturn_add_test(test_ioaddr)
coturn_add_test(test_stun_msg)

add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ${COTURN_TEST_TARGETS}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
