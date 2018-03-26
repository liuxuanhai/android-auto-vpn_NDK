# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

set(EXECUTABLE_OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/main/assets/${ANDROID_ABI}")

add_subdirectory (src/main/cpp/vpn-lib)
add_subdirectory (src/main/cpp/auto-vpn)