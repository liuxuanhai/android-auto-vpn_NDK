# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

cmake_minimum_required(VERSION 3.4.1)

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED 11)

add_library(vpn_jni SHARED ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/vpn_jni.c)

target_link_libraries(vpn_jni android log)