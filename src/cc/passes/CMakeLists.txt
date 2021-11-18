set(dyn_passes_sources JITTableRuntimePass.cpp DynamicMapOptAnalysisPass.cpp BPFMapInstrumentationPass.cpp jhash.cc utils.cpp MorpheusCompiler.cpp)

add_subdirectory(builder)

add_library(dyn_passes STATIC ${dyn_passes_sources})

target_link_libraries(dyn_passes custom_builder)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})