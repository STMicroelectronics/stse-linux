# ******************************************************************************
# cmake/rpi-toolchain.cmake
# Raspberry Pi cross-compilation toolchain for CMake
#
# Supports 64-bit (aarch64) Raspberry Pi OS (Pi 3, 4, 5, Zero 2 W)
# and 32-bit (armhf) Raspberry Pi OS (Pi 2, 3, 4, Zero).
#
# Usage:
#   64-bit target (RPi OS 64-bit / Debian aarch64):
#     cmake -B build/rpi \
#       -DCMAKE_TOOLCHAIN_FILE=cmake/rpi-toolchain.cmake \
#       -DRPI_ARCH=arm64 \
#       -DCMAKE_SYSROOT=/path/to/rpi-sysroot \
#       -DDEPLOY_TARGET=pi@raspberrypi.local
#
#   32-bit target (RPi OS 32-bit / Debian armhf):
#     cmake -B build/rpi \
#       -DCMAKE_TOOLCHAIN_FILE=cmake/rpi-toolchain.cmake \
#       -DRPI_ARCH=armhf \
#       -DCMAKE_SYSROOT=/path/to/rpi-sysroot \
#       -DDEPLOY_TARGET=pi@raspberrypi.local
#
# ******************************************************************************

set(CMAKE_SYSTEM_NAME Linux)

# Target architecture: default to arm64 (aarch64), allow armhf (32-bit)
set(RPI_ARCH "arm64" CACHE STRING "Raspberry Pi architecture: arm64 (aarch64) or armhf (32-bit)")

if(RPI_ARCH STREQUAL "arm64" OR RPI_ARCH STREQUAL "aarch64")
    set(CMAKE_SYSTEM_PROCESSOR aarch64)
    set(CROSS_COMPILE "aarch64-linux-gnu-" CACHE STRING "Cross-compiler prefix")
elseif(RPI_ARCH STREQUAL "armhf" OR RPI_ARCH STREQUAL "arm32")
    set(CMAKE_SYSTEM_PROCESSOR arm)
    set(CROSS_COMPILE "arm-linux-gnueabihf-" CACHE STRING "Cross-compiler prefix")
    # Raspberry Pi 2/3/4/Zero 2W in 32-bit mode
    set(_RPI_FLAGS "-mfpu=neon-vfpv4 -mfloat-abi=hard")
    set(CMAKE_C_FLAGS_INIT "${_RPI_FLAGS}" CACHE STRING "" FORCE)
else()
    message(FATAL_ERROR "Unsupported RPI_ARCH: ${RPI_ARCH}. Use 'arm64' or 'armhf'.")
endif()

# Compiler and tools
set(CMAKE_C_COMPILER   "${CROSS_COMPILE}gcc"     CACHE FILEPATH "" FORCE)
set(CMAKE_AR           "${CROSS_COMPILE}ar"      CACHE FILEPATH "" FORCE)
set(CMAKE_STRIP        "${CROSS_COMPILE}strip"   CACHE FILEPATH "" FORCE)
set(CMAKE_OBJCOPY      "${CROSS_COMPILE}objcopy" CACHE FILEPATH "" FORCE)
set(CMAKE_LINKER       "${CROSS_COMPILE}ld"      CACHE FILEPATH "" FORCE)
set(CMAKE_RANLIB       "${CROSS_COMPILE}ranlib"  CACHE FILEPATH "" FORCE)

# Sysroot search policy
if(CMAKE_SYSROOT)
    message(STATUS "[rpi-toolchain] Sysroot: ${CMAKE_SYSROOT}")
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
endif()
