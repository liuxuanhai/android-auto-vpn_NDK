# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

cmake_minimum_required(VERSION 3.4.1)

set(EXECUTABLE_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/main/assets/${ANDROID_ABI}")

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED 11)

add_library(vpn_jni SHARED ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/vpn_jni.c)


find_library(log-lib log)

target_link_libraries(vpn_jni {log-lib})

#Header files
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/)

#Cpp files
add_library(ipnetwork STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/ipnetwork.cpp )
add_library(pping STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/pping.cpp )


add_executable(auto_vpn ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/auto_vpn.cpp)
target_link_libraries(auto_vpn pping ipnetwork)