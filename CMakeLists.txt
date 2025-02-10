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
        src/core/error.ixx
        src/core/exception.ixx
        src/core/flags.ixx
        src/core/functions.ixx
        src/core/info.ixx
        src/core/user.ixx
        src/core/version.ixx

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
        src/token/token.info.ixx)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_23)
target_compile_options(${PROJECT_NAME} PRIVATE /W4)
target_include_directories(${PROJECT_NAME} PUBLIC include)

add_subdirectory(test)

enable_testing()
