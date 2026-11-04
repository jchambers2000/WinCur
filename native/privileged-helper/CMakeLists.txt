cmake_minimum_required(VERSION 3.25)

cmake_policy(SET CMP0091 NEW)

project(
    WinCurPrivilegedHelper
    VERSION 1.0.0
    DESCRIPTION "WinCur native privileged-helper confirmation foundation"
    LANGUAGES CXX RC
)

if(NOT MSVC)
    message(FATAL_ERROR "WinCur.PrivilegedHelper must be built with Microsoft MSVC.")
endif()

if(MSVC_VERSION LESS 1930 OR MSVC_VERSION GREATER_EQUAL 1950)
    message(FATAL_ERROR "WinCur.PrivilegedHelper requires the MSVC v143 compiler toolset.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "WinCur.PrivilegedHelper supports only Windows x64 builds.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include(CTest)

function(wincur_harden_target target)
    target_compile_definitions(
        ${target}
        PRIVATE
            UNICODE
            _UNICODE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            _WIN32_WINNT=0x0A00
    )
    target_compile_options(
        ${target}
        PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/W4>
            $<$<COMPILE_LANGUAGE:CXX>:/WX>
            $<$<COMPILE_LANGUAGE:CXX>:/permissive->
            $<$<COMPILE_LANGUAGE:CXX>:/sdl>
            $<$<COMPILE_LANGUAGE:CXX>:/GS>
            $<$<COMPILE_LANGUAGE:CXX>:/guard:cf>
            $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
            $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
            $<$<COMPILE_LANGUAGE:CXX>:/Zc:inline>
            $<$<COMPILE_LANGUAGE:CXX>:/Zc:preprocessor>
            $<$<COMPILE_LANGUAGE:CXX>:/Zc:wchar_t>
            $<$<COMPILE_LANGUAGE:CXX>:/ZH:SHA_256>
            $<$<COMPILE_LANGUAGE:CXX>:/Brepro>
    )
endfunction()

function(wincur_harden_executable target)
    wincur_harden_target(${target})
    target_link_options(
        ${target}
        PRIVATE
            /DYNAMICBASE
            /HIGHENTROPYVA
            /NXCOMPAT
            /GUARD:CF
            /CETCOMPAT
            /DEPENDENTLOADFLAG:0x800
            /INCREMENTAL:NO
            /OPT:REF
            /OPT:ICF
            /Brepro
    )
endfunction()

add_library(
    wincur_helper_core
    STATIC
        src/protocol.cpp
        src/stub_backend.cpp
        src/inspection.cpp
        src/confirmation.cpp
        src/transaction.cpp
)
target_include_directories(wincur_helper_core PUBLIC include)
wincur_harden_target(wincur_helper_core)

add_library(
    wincur_helper_windows
    STATIC
        src/registry_security.cpp
        src/windows_confirmation.cpp
        src/windows_inspection.cpp
        src/windows_transaction_store.cpp
)
target_include_directories(wincur_helper_windows PUBLIC include)
target_link_libraries(
    wincur_helper_windows
    PUBLIC
        wincur_helper_core
        Advapi32
        Bcrypt
        Comctl32
        Ole32
)
wincur_harden_target(wincur_helper_windows)

add_executable(
    WinCur.PrivilegedHelper
    WIN32
        src/main.cpp
        src/operation_mutex.cpp
        resources/helper.rc
)
target_include_directories(
    WinCur.PrivilegedHelper
    PRIVATE
        include
        resources
)
target_link_libraries(
    WinCur.PrivilegedHelper
    PRIVATE
        wincur_helper_core
        wincur_helper_windows
        Advapi32
        Comctl32
        Shell32
)
wincur_harden_executable(WinCur.PrivilegedHelper)
target_link_options(
    WinCur.PrivilegedHelper
    PRIVATE
        /MANIFEST:NO
)

if(BUILD_TESTING)
    add_executable(
        WinCur.PrivilegedHelper.ParserTests
        tests/parser_tests.cpp
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.ParserTests
        PRIVATE
            wincur_helper_core
    )
    wincur_harden_executable(WinCur.PrivilegedHelper.ParserTests)
    add_test(
        NAME privileged_helper_parser
        COMMAND WinCur.PrivilegedHelper.ParserTests
    )

    add_executable(
        WinCur.PrivilegedHelper.TransactionTests
        tests/transaction_tests.cpp
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.TransactionTests
        PRIVATE
            wincur_helper_core
    )
    wincur_harden_executable(WinCur.PrivilegedHelper.TransactionTests)
    add_test(
        NAME privileged_helper_transactions
        COMMAND WinCur.PrivilegedHelper.TransactionTests
    )

    add_executable(
        WinCur.PrivilegedHelper.RegistrySecurityTests
        tests/registry_security_tests.cpp
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.RegistrySecurityTests
        PRIVATE
            wincur_helper_windows
    )
    wincur_harden_executable(WinCur.PrivilegedHelper.RegistrySecurityTests)
    add_test(
        NAME privileged_helper_registry_security
        COMMAND WinCur.PrivilegedHelper.RegistrySecurityTests
    )

    add_executable(
        WinCur.PrivilegedHelper.InspectionTests
        tests/inspection_tests.cpp
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.InspectionTests
        PRIVATE
            wincur_helper_core
    )
    wincur_harden_executable(WinCur.PrivilegedHelper.InspectionTests)
    add_test(
        NAME privileged_helper_inspection
        COMMAND WinCur.PrivilegedHelper.InspectionTests
    )

    add_executable(
        WinCur.PrivilegedHelper.ConfirmationTests
        tests/confirmation_tests.cpp
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.ConfirmationTests
        PRIVATE
            wincur_helper_core
    )
    wincur_harden_executable(WinCur.PrivilegedHelper.ConfirmationTests)
    add_test(
        NAME privileged_helper_confirmation
        COMMAND WinCur.PrivilegedHelper.ConfirmationTests
    )

    add_executable(
        WinCur.PrivilegedHelper.LifecycleTests
        tests/lifecycle_tests.cpp
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.LifecycleTests
        PRIVATE
            wincur_helper_core
    )
    wincur_harden_executable(WinCur.PrivilegedHelper.LifecycleTests)
    add_test(
        NAME privileged_helper_lifecycle
        COMMAND WinCur.PrivilegedHelper.LifecycleTests
    )
endif()

option(
    WINCUR_BUILD_INSPECTION_INTEGRATION_TESTS
    "Build opt-in read-only Windows security inspection tests"
    OFF
)
if(WINCUR_BUILD_INSPECTION_INTEGRATION_TESTS)
    add_executable(
        WinCur.PrivilegedHelper.InspectionIntegrationTests
        tests/inspection_integration_tests.cpp
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.InspectionIntegrationTests
        PRIVATE
            wincur_helper_windows
    )
    wincur_harden_executable(
        WinCur.PrivilegedHelper.InspectionIntegrationTests
    )
endif()

option(
    WINCUR_BUILD_CONFIRMATION_INTEGRATION_TESTS
    "Build opt-in disposable-VM native confirmation dialog tests"
    OFF
)
if(WINCUR_BUILD_CONFIRMATION_INTEGRATION_TESTS)
    add_executable(
        WinCur.PrivilegedHelper.ConfirmationIntegrationTests
            tests/confirmation_integration_tests.cpp
            resources/helper.rc
    )
    target_include_directories(
        WinCur.PrivilegedHelper.ConfirmationIntegrationTests
        PRIVATE
            include
            resources
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.ConfirmationIntegrationTests
        PRIVATE
            wincur_helper_windows
    )
    wincur_harden_executable(
        WinCur.PrivilegedHelper.ConfirmationIntegrationTests
    )
    target_link_options(
        WinCur.PrivilegedHelper.ConfirmationIntegrationTests
        PRIVATE
            /MANIFEST:NO
    )
endif()

option(
    WINCUR_BUILD_REGISTRY_INTEGRATION_TESTS
    "Build destructive HKLM tests for an explicitly approved disposable VM"
    OFF
)
if(WINCUR_BUILD_REGISTRY_INTEGRATION_TESTS)
    add_library(
        wincur_helper_windows_registry_integration
        STATIC
            src/registry_security.cpp
            src/windows_transaction_store.cpp
    )
    target_include_directories(
        wincur_helper_windows_registry_integration
        PUBLIC
            include
    )
    target_link_libraries(
        wincur_helper_windows_registry_integration
        PUBLIC
            wincur_helper_core
            Advapi32
            Ole32
    )
    target_compile_definitions(
        wincur_helper_windows_registry_integration
        PUBLIC
            WINCUR_TEST_REGISTRY_NAMESPACE=1
    )
    wincur_harden_target(wincur_helper_windows_registry_integration)

    add_executable(
        WinCur.PrivilegedHelper.RegistryIntegrationTests
        tests/registry_integration_tests.cpp
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.RegistryIntegrationTests
        PRIVATE
            wincur_helper_windows_registry_integration
    )
    wincur_harden_executable(WinCur.PrivilegedHelper.RegistryIntegrationTests)

    add_executable(
        WinCur.PrivilegedHelper.ProductionPathAcceptanceTests
        tests/production_path_acceptance_tests.cpp
    )
    target_link_libraries(
        WinCur.PrivilegedHelper.ProductionPathAcceptanceTests
        PRIVATE
            wincur_helper_windows
    )
    wincur_harden_executable(
        WinCur.PrivilegedHelper.ProductionPathAcceptanceTests
    )
endif()
