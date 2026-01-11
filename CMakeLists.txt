cmake_minimum_required(VERSION 3.14)
project(ecewo_cors VERSION 0.1.0 LANGUAGES C)

add_library(ecewo_cors
  src/ecewo-cors.c
)

add_library(ecewo::cors ALIAS ecewo_cors)

target_include_directories(ecewo_cors PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
)

if (PROJECT_IS_TOP_LEVEL AND NOT TARGET ecewo::ecewo)
  include(FetchContent)

  FetchContent_Declare(
    ecewo
    GIT_REPOSITORY https://github.com/savashn/ecewo.git
    GIT_TAG        dev
    GIT_SHALLOW    TRUE
  )

  FetchContent_MakeAvailable(ecewo)
endif()

target_link_libraries(ecewo_cors PUBLIC ecewo::ecewo)

if (PROJECT_IS_TOP_LEVEL AND TARGET ecewo::ecewo)
  ecewo_add_plugin(mock)
  
  option(ECEWO_CORS_BUILD_TESTS "Build tests" ON)
  
  if (ECEWO_CORS_BUILD_TESTS)
    enable_testing()
    
    function(add_cors_test test_name)
      set(target_name ecewo_cors_${test_name}_test)
      
      add_executable(${target_name} tests/test-${test_name}-cors.c)
      
      target_include_directories(${target_name}
        PRIVATE
          ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${CMAKE_CURRENT_SOURCE_DIR}/tests
      )
      
      target_link_libraries(${target_name}
        PRIVATE
          ecewo::ecewo
          ecewo::cors
          ecewo::mock
      )
      
      if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
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
endif()
