# Locates the blytz library
# This module defines
# BLYTZ_LIBRARY, the name of the library to link against
# BLYTZ_FOUND, if false, do not try to link to SDL
# BLYTZ_INCLUDE_DIR, where to find blytz-api.h
#
# BLYTZ_DIR: specify optional search dir

FIND_PATH(BLYTZ_INCLUDE_DIR blytz-api.h
  HINTS
	$ENV{BLYTZ_DIR}
  PATH_SUFFIXES include/blytz include
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local
  /usr
  /opt/local
  /opt
)

FIND_LIBRARY(BLYTZ_LIBRARY 
  NAMES libblytz.so
  HINTS
	$ENV{BLYTZ_DIR}
  PATH_SUFFIXES lib64 lib
  PATHS
  /sw
  /opt/local
  /opt
)

IF(BLYTZ_LIBRARY AND BLYTZ_INCLUDE_DIR)
	SET(BLYTZ_FOUND "YES")
ENDIF(BLYTZ_LIBRARY AND BLYTZ_INCLUDE_DIR)

