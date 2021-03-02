cmake_minimum_required (VERSION 3.5)

project(latPerf)

set (CMAKE_CXX_STANDARD 11)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
ADD_SUBDIRECTORY(src bin)