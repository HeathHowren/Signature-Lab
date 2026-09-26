include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(Catch2)

add_executable(siglab_tests
    test_builder.cpp
    test_decoder.cpp
    test_module_image.cpp
    test_pattern.cpp
    test_references.cpp
    test_report.cpp
)
target_include_directories(siglab_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(siglab_tests PRIVATE siglab_core siglab_warnings Catch2::Catch2WithMain)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(siglab_tests)
