CMAKE_MINIMUM_REQUIRED(VERSION 3.5)
PROJECT(lsquic-tutorial C)

SET(DEFAULT_BUILD_TYPE Debug)
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $ENV{EXTRA_CFLAGS}")

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

ADD_SUBDIRECTORY(boringssl)

INCLUDE_DIRECTORIES(boringssl/include)
INCLUDE_DIRECTORIES(lsquic/include)
INCLUDE_DIRECTORIES(lsquic/src/liblsquic)       # For lsquic_xxhash.h
ADD_SUBDIRECTORY(lsquic/src/liblsquic)

INCLUDE_DIRECTORIES(libev)
ADD_EXECUTABLE(tut tut.c)
SET(LIBS lsquic crypto ssl z m)
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # If using older glibc, need to link with -lrt.  See clock_getres(2).
    EXECUTE_PROCESS(
        COMMAND ${PROJECT_SOURCE_DIR}/print-glibc-version.sh ${CMAKE_C_COMPILER}
        OUTPUT_VARIABLE GLIBC_VERSION)
    IF(NOT GLIBC_VERSION EQUAL "" AND GLIBC_VERSION VERSION_LESS 2.17)
        SET(LIBS ${LIBS} rt)
    ENDIF()
ENDIF()
TARGET_LINK_LIBRARIES(tut ${LIBS})
