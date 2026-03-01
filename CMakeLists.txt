
cmake_minimum_required(VERSION 3.20)

project(pe-parser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(pe-parser
	include/winntdef.h
	include/pe.h
	src/pe.cpp
	src/main.cpp
)