cmake_minimum_required(VERSION 3.14)
project(ecewo_cors VERSION 0.2.0 LANGUAGES C)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

option(ECEWO_CORS_BUILD_SHARED "Build ecewo-cors as a shared library" OFF)
option(ECEWO_CORS_BUILD_TESTS "Build ecewo-cors tests" ${PROJECT_IS_TOP_LEVEL})

if(NOT TARGET ecewo::ecewo)
  if(DEFINED ECEWO_BUILD_SHARED)
    set(ECEWO_CORS_BUILD_SHARED "${ECEWO_BUILD_SHARED}" CACHE BOOL "" FORCE)
  endif()

  set(ECEWO_BUILD_SHARED "${ECEWO_CORS_BUILD_SHARED}" CACHE BOOL "" FORCE)

  include(FetchContent)
  FetchContent_Declare(
    ecewo
    GIT_REPOSITORY https://github.com/ecewo/ecewo.git
    GIT_TAG v4.0.0
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(ecewo)
endif()

if(ECEWO_CORS_BUILD_SHARED)
  add_library(ecewo_cors SHARED src/ecewo-cors.c)
  message(STATUS "Building ecewo_cors as SHARED library")
else()
  add_library(ecewo_cors STATIC src/ecewo-cors.c)
  message(STATUS "Building ecewo_cors as STATIC library")
endif()

add_library(ecewo::cors ALIAS ecewo_cors)

include(GenerateExportHeader)
generate_export_header(ecewo_cors
  BASE_NAME ECEWO_CORS
  EXPORT_FILE_NAME "${CMAKE_CURRENT_BINARY_DIR}/include/ecewo-cors-export.h"
)

target_include_directories(ecewo_cors PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(ecewo_cors PUBLIC ecewo::ecewo)

set_target_properties(ecewo_cors PROPERTIES
  OUTPUT_NAME ecewo_cors
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  EXPORT_NAME cors
  C_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
  POSITION_INDEPENDENT_CODE ON
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(ecewo_cors PRIVATE
    -Wall -Wextra -Wstrict-prototypes -Wincompatible-pointer-types
  )
endif()

if(ECEWO_CORS_BUILD_TESTS AND TARGET ecewo::ecewo)
  ecewo_add(mock@dev)
  enable_testing()

  function(add_cors_test test_name)
    set(target_name ecewo_cors_${test_name}_test)

    add_executable(${target_name} tests/test-${test_name}-cors.c)

    target_include_directories(${target_name} PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/src
      ${CMAKE_CURRENT_SOURCE_DIR}/tests
      ${CMAKE_CURRENT_BINARY_DIR}/include
    )

    target_link_libraries(${target_name} PRIVATE
      ecewo::ecewo
      ecewo::cors
      ecewo::mock
    )

    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
      target_compile_options(${target_name} PRIVATE
        -Wall -Wextra -Werror
        -Wstrict-prototypes
        -Wincompatible-pointer-types
        -Wno-unused-parameter
      )
    endif()

    add_test(NAME ecewo_cors_${test_name} COMMAND ${target_name})
  endfunction()

  add_cors_test(default)
  add_cors_test(custom)
endif()
