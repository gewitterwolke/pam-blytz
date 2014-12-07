cmake_minimum_required(VERSION 2.8)

project(pam_blytz)

set(CMAKE_VERBOSE_MAKEFILE OFF)

FILE(GLOB pam_blytz_src_files
	${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "cmake/modules/")                

include(FindBlytz)
if(NOT BLYTZ_FOUND)
	message(SEND_ERROR "Couldn't find blytz library.")
endif(NOT BLYTZ_FOUND)

include(FindSSH)
if(NOT SSH_FOUND)
	message(SEND_ERROR "Couldn't find libssh library.")
endif(NOT SSH_FOUND)

include(FindPAM)
if(NOT PAM_FOUND)
	message(SEND_ERROR "Couldn't find pam library.")
endif(NOT PAM_FOUND)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "cmake/modules/")

include_directories(. ./include ${LIBSSH_INCLUDE_DIRS} ${BLYTZ_INCLUDE_DIR})

add_library(pam_blytz 
	SHARED ${pam_blytz_src_files})

SET_TARGET_PROPERTIES(
	pam_blytz 
	PROPERTIES
	OUTPUT_NAME pam_blytz
	PREFIX ""
	)
target_link_libraries(pam_blytz LINK_PUBLIC ${LIBSSH_LIBRARIES} ${BLYTZ_LIBRARY})

IF(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	SET(LIBSECURITYDIR "/lib64/security" CACHE PATH "PAM module installation location")
ELSE(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	SET(LIBSECURITYDIR "/lib/security" CACHE PATH "PAM module
	installation location")
ENDIF(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")

IF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
	install(TARGETS pam_blytz LIBRARY DESTINATION lib)
ELSE()
	install(TARGETS pam_blytz LIBRARY DESTINATION ${LIBSECURITYDIR})
ENDIF()

