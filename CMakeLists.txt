cmake_minimum_required(VERSION 3.12)
project(s63lib VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

cmake_policy(SET CMP0074 NEW)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Build options
option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TESTS "Build test programs" ON)

# Enable warnings
if(MSVC)
    add_compile_options(/W4 /WX-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find zlib
find_package(ZLIB REQUIRED)

get_target_property(ZLIB_LIBS ZLIB::ZLIB INTERFACE_LINK_LIBRARIES)
message(STATUS "ZLIB_FOUND=${ZLIB_FOUND}")
message(STATUS "ZLIB_INCLUDE_DIRS=${ZLIB_INCLUDE_DIRS}")
message(STATUS "ZLIB_LIBRARIES=${ZLIB_LIBRARIES}")
# =============================================================================
# Main Library
# =============================================================================
add_library(${PROJECT_NAME}
    src/s63.cpp
    src/s63client.cpp
    src/utils.hpp
    src/blowfish.cpp
    src/simple_zip.cpp
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
    ZLIB::ZLIB
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# =============================================================================
# Examples
# =============================================================================
if(BUILD_EXAMPLES)
    add_executable(decrypt_example
        examples/decrypt.cpp
    )
    
    target_link_libraries(decrypt_example
        PRIVATE
        ${PROJECT_NAME}
        ZLIB::ZLIB
    )
    
    target_include_directories(decrypt_example
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    
    set_target_properties(decrypt_example PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/examples"
    )

    target_compile_definitions(decrypt_example PRIVATE
        DATA_PATH="${CMAKE_CURRENT_SOURCE_DIR}/examples/test_cells"
    )

endif()

# =============================================================================
# Tests
# =============================================================================
if(BUILD_TESTS)
    enable_testing()
    
    add_executable(${PROJECT_NAME}_tests
        tests/test.cpp
    )
    
    target_link_libraries(${PROJECT_NAME}_tests
        PRIVATE
        ${PROJECT_NAME}
        ZLIB::ZLIB
    )
    
    target_include_directories(${PROJECT_NAME}_tests
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src     # For internal headers
    )
    
    set_target_properties(${PROJECT_NAME}_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/tests"
    )
    
    add_test(NAME ${PROJECT_NAME}_tests
        COMMAND ${PROJECT_NAME}_tests
    )
endif()

# =============================================================================
# Print build configuration
# =============================================================================
message(STATUS "Build configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  ZLIB found: ${ZLIB_FOUND}")