cmake_minimum_required(VERSION 3.30 FATAL_ERROR)
project(pkcs11 LANGUAGES CXX VERSION 0.0.1)

set(CMAKE_CXX_SCAN_FOR_MODULES ON)

add_library(${PROJECT_NAME})
target_sources(${PROJECT_NAME}
        PUBLIC
        FILE_SET cxx_modules
        TYPE CXX_MODULES
        FILES
        # PKCS#11
        src/pkcs11.ixx

        # Core
        src/core/core.ixx
        src/core/core.bitmask.ixx
        src/core/core.error.ixx
        src/core/core.exception.ixx
        src/core/core.flags.ixx
        src/core/core.functions.ixx
        src/core/core.info.ixx
        src/core/core.user.ixx
        src/core/core.version.ixx

        # Decrypt
        src/decrypt/decrypt.ixx

        # Encrypt
        src/encrypt/encrypt.ixx

        # Mechanism
        src/mechanism/mechanism.flags.ixx
        src/mechanism/mechanism.info.ixx

        # Session
        src/session/session.ixx
        src/session/session.flags.ixx
        src/session/session.info.ixx
        src/session/session.state.ixx

        # Slot
        src/slot/slot.ixx
        src/slot/slot.flags.ixx
        src/slot/slot.info.ixx

        # Token
        src/token/token.flags.ixx
        src/token/token.info.ixx

        # Verify
        src/verify/verify.ixx
)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_23)
target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W3>
        $<$<CXX_COMPILER_ID:Clang>:-Wall -Wno-elaborated-enum-class>
        $<$<CXX_COMPILER_ID:GNU>:-Wall>)
target_include_directories(${PROJECT_NAME} PUBLIC include)

add_subdirectory(test)

enable_testing()
