include(FindGFlags.cmake)
include(FindGlog.cmake)
#find_package(gflags REQUIRED)
#find_package(glog REQUIRED)
include(FindPCAP.cmake)

aux_source_directory(. DIR_SRCS)

add_executable(latPerf ${DIR_SRCS})

target_link_libraries(latPerf gflags glog ${PCAP_LIBRARY})

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/../)