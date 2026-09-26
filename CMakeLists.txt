# 3.28 for EXCLUDE_FROM_ALL in FetchContent_Declare, which keeps Zydis's own
# tools and tests out of the default build.
cmake_minimum_required(VERSION 3.28)

project(SignatureLab VERSION 1.0.0 LANGUAGES C CXX)

if(NOT MSVC)
    message(FATAL_ERROR "Signature Lab is an x64dbg plugin and builds with MSVC only.")
endif()

get_property(_sl_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _sl_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Static CRT. A plugin that needs a VC++ redistributable x64dbg does not ship
# fails to load with nothing in the log but "LoadLibrary failed", which is the
# most common complaint on every x64dbg plugin's issue tracker.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(SIGLAB_BUILD_TESTS "Build the unit tests" ON)
option(SIGLAB_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(SIGLAB_BUILD_X32 "From a 64-bit configure, also build the 32-bit plugin for x32dbg" ON)
option(SIGLAB_BUILD_PLUGIN "Build the x64dbg plugin (off builds only the core and its tests)" ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(SIGLAB_ARCH x64)
else()
    set(SIGLAB_ARCH x32)
endif()

include(FetchContent)

# ---------------------------------------------------------------------------
# Dependencies, all pinned (see THIRD_PARTY_NOTICES.md)
# ---------------------------------------------------------------------------

# Zydis: the x86/x64 decoder (MIT). The same commit Pointer Lab pins, so the
# two tools disassemble identically.
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES   OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS      OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN    OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN        OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG a2278f1d254e492f6a6b39f6cb5d1f5d515659dc # v4.1.1
    EXCLUDE_FROM_ALL
)

# The x64dbg plugin SDK from the 2026.05.27 release, the snapshot The Game
# Hacker's Handbook installs. Pinned by hash: the SDK is append-only in
# principle, but a plugin built against headers newer than the debugger it
# loads into can call exports that do not exist yet.
FetchContent_Declare(
    x64dbgsdk
    URL https://github.com/x64dbg/x64dbg/releases/download/2026.05.27/x64dbg-pluginsdk.zip
    URL_HASH SHA256=52cbb9652dcae9a386d8ca94b46c3a291c3e791b36d1407fb1e1f0d36515e10f
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(zydis x64dbgsdk)

# ---------------------------------------------------------------------------
# Warnings, first-party targets only
# ---------------------------------------------------------------------------

add_library(siglab_warnings INTERFACE)
# /w44062: a switch over an enum that misses an enumerator is an error. Every
# enum in the core is switched over somewhere, and a new ByteReason that the
# policy forgot about would otherwise be silently kept.
target_compile_options(siglab_warnings INTERFACE /W4 /w44062 /permissive- /Zc:__cplusplus /utf-8)
if(SIGLAB_WARNINGS_AS_ERRORS)
    target_compile_options(siglab_warnings INTERFACE /WX)
endif()

# ---------------------------------------------------------------------------
# siglab_core: everything that decides what a signature is. No x64dbg header
# is included here, so the tests link the real logic without a debugger.
# ---------------------------------------------------------------------------

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/Version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/Version.h
    @ONLY
)

add_library(siglab_core STATIC
    src/core/Builder.cpp
    src/core/Decoder.cpp
    src/core/ModuleImage.cpp
    src/core/Pattern.cpp
    src/core/Report.cpp
    src/core/Wildcarder.cpp
)
target_compile_features(siglab_core PUBLIC cxx_std_20)
target_include_directories(siglab_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_compile_definitions(siglab_core PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(siglab_core PUBLIC Zydis PRIVATE siglab_warnings)

# ---------------------------------------------------------------------------
# The plugin: SignatureLab.dp64 from a 64-bit build, SignatureLab.dp32 from a
# 32-bit one. x64dbg finds plugins by extension, not by name.
# ---------------------------------------------------------------------------

if(SIGLAB_BUILD_PLUGIN)

add_library(x64dbg_sdk INTERFACE)
# SYSTEM, so /W4 /WX applies to our code and not to the SDK's headers.
target_include_directories(x64dbg_sdk SYSTEM INTERFACE ${x64dbgsdk_SOURCE_DIR})
if(SIGLAB_ARCH STREQUAL "x64")
    target_link_libraries(x64dbg_sdk INTERFACE
        ${x64dbgsdk_SOURCE_DIR}/x64dbg.lib
        ${x64dbgsdk_SOURCE_DIR}/x64bridge.lib)
else()
    target_link_libraries(x64dbg_sdk INTERFACE
        ${x64dbgsdk_SOURCE_DIR}/x32dbg.lib
        ${x64dbgsdk_SOURCE_DIR}/x32bridge.lib)
endif()

add_library(SignatureLab SHARED
    src/plugin/Actions.cpp
    src/plugin/BridgeMemoryView.cpp
    src/plugin/Clipboard.cpp
    src/plugin/Dialog.cpp
    src/plugin/Plugin.cpp
    src/plugin/Settings.cpp
    resources/SignatureLab.rc
)
target_link_libraries(SignatureLab PRIVATE siglab_core siglab_warnings x64dbg_sdk comctl32)
set_source_files_properties(resources/SignatureLab.rc PROPERTIES
    INCLUDE_DIRECTORIES "${CMAKE_CURRENT_BINARY_DIR}/generated;${CMAKE_CURRENT_SOURCE_DIR}/resources;${CMAKE_CURRENT_SOURCE_DIR}/src/plugin"
)
if(SIGLAB_ARCH STREQUAL "x64")
    set_target_properties(SignatureLab PROPERTIES SUFFIX ".dp64")
else()
    set_target_properties(SignatureLab PROPERTIES SUFFIX ".dp32")
endif()
target_compile_definitions(SignatureLab PRIVATE UNICODE _UNICODE)

endif()

# ---------------------------------------------------------------------------
# The 32-bit plugin, from the 64-bit configure
#
# MSVC's architecture comes from the generator, not from a target property,
# so a Win32 binary needs its own configure. This re-runs this same project
# with -A Win32, reusing the sources already fetched above so nothing is
# downloaded twice.
# ---------------------------------------------------------------------------

if(SIGLAB_ARCH STREQUAL "x64" AND SIGLAB_BUILD_X32 AND SIGLAB_BUILD_PLUGIN)
    include(ExternalProject)
    ExternalProject_Add(siglab_x32
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
        BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/x32-build
        CMAKE_GENERATOR ${CMAKE_GENERATOR}
        CMAKE_GENERATOR_PLATFORM Win32
        CMAKE_ARGS
            -DSIGLAB_BUILD_TESTS=${SIGLAB_BUILD_TESTS}
            -DSIGLAB_BUILD_X32=OFF
            -DSIGLAB_WARNINGS_AS_ERRORS=${SIGLAB_WARNINGS_AS_ERRORS}
            -DFETCHCONTENT_SOURCE_DIR_ZYDIS=${zydis_SOURCE_DIR}
            -DFETCHCONTENT_SOURCE_DIR_X64DBGSDK=${x64dbgsdk_SOURCE_DIR}
            -DFETCHCONTENT_SOURCE_DIR_CATCH2=${CMAKE_CURRENT_BINARY_DIR}/_deps/catch2-src
        BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG>
        # ExternalProject stamps its build step on first success and does not
        # know the shared sources changed. Without this the .dp32 freezes at
        # its first build while the .dp64 moves on.
        BUILD_ALWAYS 1
        INSTALL_COMMAND ""
        BUILD_BYPRODUCTS <BINARY_DIR>/$<CONFIG>/SignatureLab.dp32
    )
    add_dependencies(siglab_x32 SignatureLab)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(SIGLAB_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
    if(TARGET siglab_x32)
        # The 32-bit test binary exercises the core with a 32-bit size_t and
        # pointer, which is how x32dbg runs it.
        add_test(NAME siglab_tests_x32
                 COMMAND ${CMAKE_CURRENT_BINARY_DIR}/x32-build/tests/$<CONFIG>/siglab_tests.exe)
    endif()
endif()

# ---------------------------------------------------------------------------
# Package: a zip laid out like an x64dbg folder, so it extracts straight over
# one.
# ---------------------------------------------------------------------------

if(TARGET SignatureLab)
    install(TARGETS SignatureLab RUNTIME DESTINATION release/${SIGLAB_ARCH}/plugins)
endif()
if(TARGET siglab_x32)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/x32-build/$<CONFIG>/SignatureLab.dp32 DESTINATION release/x32/plugins)
endif()
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md
    ${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md
    DESTINATION SignatureLab
)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/docs/usage.md DESTINATION SignatureLab/docs)

set(CPACK_PACKAGE_NAME "SignatureLab")
set(CPACK_PACKAGE_VENDOR "Game Reversal Club")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "SignatureLab-v${PROJECT_VERSION}")
set(CPACK_GENERATOR "ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Signature maker plugin for x64dbg")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
include(CPack)
