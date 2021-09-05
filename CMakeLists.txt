cmake_minimum_required(VERSION 2.8)
INCLUDE (CheckIncludeFiles)
INCLUDE(FindPkgConfig)

PROJECT(usteer-influxdb C)

SET(SOURCES ubus.c usteer-influxdb.c)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations)

FIND_LIBRARY(libjson NAMES json-c json)
ADD_EXECUTABLE(usteer-influxdb ${SOURCES})

TARGET_LINK_LIBRARIES(usteer-influxdb ubox ubus blobmsg_json ${libjson})


SET(CMAKE_INSTALL_PREFIX /usr)

INSTALL(TARGETS usteer-influxdb
	RUNTIME DESTINATION bin
)
