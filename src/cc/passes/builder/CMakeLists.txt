add_library(custom_builder
        irbuilderbpf.cpp
        )

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})