cmake_minimum_required(VERSION 3.30 FATAL_ERROR)
project(pkcs11-test LANGUAGES CXX)

include(FetchContent)
set(FETCHCONTENT_QUIET)
FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest
        GIT_TAG main)
FetchContent_MakeAvailable(googletest)
include(GoogleTest)

add_executable(${PROJECT_NAME}
        common/version_test.cpp

        slot/slot_flags_test.cpp
        slot/slot_info_test.cpp

        token/token_flags_test.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE pkcs11 gtest gmock gtest_main)
target_compile_options(${PROJECT_NAME} PRIVATE /W4)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_23)

gtest_discover_tests(${PROJECT_NAME})
