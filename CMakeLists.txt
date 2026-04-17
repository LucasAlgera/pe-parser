cmake_minimum_required(VERSION 3.20)
project(pe-parser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/external/imgui)

add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
)

target_include_directories(imgui PUBLIC
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

add_executable(pe-parser
    src/pe.cpp
    src/main.cpp
    src/pe_imgui.cpp
)

target_link_options(pe-parser PRIVATE /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup)

target_sources(pe-parser PRIVATE
    include/winntdef.h
    include/pe.h
    include/pe_imgui.h
)

target_include_directories(pe-parser PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(pe-parser PRIVATE
    imgui
    d3d11
    dxgi
)