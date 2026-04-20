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
endfunction()

coturn_add_test(test_ioaddr)
coturn_add_test(test_stun_msg)
