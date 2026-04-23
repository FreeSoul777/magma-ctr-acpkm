cmake_minimum_required(VERSION 3.10)
project(MagmaACPKM C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

option(BUILD_TESTS "Build test suite" OFF)
option(DEV_MODE "Development mode (disable integrity check)" OFF)

add_library(utils STATIC
    src/utils/utils.c
    src/utils/logging.c
)

add_library(core STATIC
    src/core/magma.c
    src/core/ctr_acpkm.c
)
target_link_libraries(core utils)

add_executable(magma src/main.c)
target_link_libraries(magma core utils)

if(BUILD_TESTS)
    add_executable(magma_tests
        src/tests/main.c
        src/tests/test_magma.c
        src/tests/test_ctr_acpkm.c
        src/tests/benchmark.c
    )
    target_link_libraries(magma_tests core utils)
    target_compile_definitions(magma_tests PRIVATE BUILD_TESTS=1)
    
    add_custom_target(check
        COMMAND ./magma_tests
        DEPENDS magma_tests
        COMMENT "Running tests..."
    )
endif()

if(DEV_MODE)
    target_compile_definitions(magma PRIVATE DEV_MODE=1)
    target_compile_definitions(core PRIVATE DEV_MODE=1)
    target_compile_definitions(utils PRIVATE DEV_MODE=1)
    if(BUILD_TESTS)
        target_compile_definitions(magma_tests PRIVATE DEV_MODE=1)
    endif()
endif()