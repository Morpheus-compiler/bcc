include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(dyn_passes_sources JITTableRuntimePass.cpp DynamicMapOptAnalysisPass.cpp BPFMapInstrumentationPass.cpp jhash.cc utils.cpp MorpheusCompiler.cpp)

find_package(yaml-cpp REQUIRED)
set(LIBS yaml-cpp)

add_subdirectory(builder)

add_library(dyn_passes STATIC ${dyn_passes_sources})

set(LIBS ${LIBS} custom_builder)

target_link_libraries(dyn_passes ${LIBS})
