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

        # Common
        src/common/common.ixx
        src/common/error.ixx
        src/common/exception.ixx
        src/common/function_list_provider.ixx
        src/common/user_type.ixx
        src/common/version.ixx

        # Core
        src/core/core.ixx
        src/core/flags.ixx
        src/core/info.ixx

        # Decrypt
        src/decrypt/decrypt.ixx

        # Encrypt
        src/encrypt/encrypt.ixx

        # Mechanism
        src/mechanism/mechanism.ixx
        src/mechanism/mechanism_flags.ixx
        src/mechanism/mechanism_info.ixx

        # Session
        src/session/session.ixx
        src/session/session_flags.ixx
        src/session/session_info.ixx
        src/session/session_state.ixx

        # Slot
        src/slot/slot.ixx
        src/slot/slot_flags.ixx
        src/slot/slot_info.ixx

        # Token
        src/token/token.ixx
        src/token/token_flags.ixx
        src/token/token_info.ixx)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_23)
target_compile_options(${PROJECT_NAME} PRIVATE /W4)
target_include_directories(${PROJECT_NAME} PUBLIC include)

add_subdirectory(test)

enable_testing()
