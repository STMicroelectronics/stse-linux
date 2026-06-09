# ******************************************************************************
# cmake/stm32mp1-toolchain.cmake
# STM32MP1 cross-compilation toolchain for CMake
#
# Target: ARM Cortex-A7, NEON/VFPv4, hard-float ABI
# Board:  STM32MP157 / STM32MP135 running OpenSTLinux
#
# Two usage modes:
#
#   Mode A — OpenSTLinux SDK (recommended):
#     source /opt/st/stm32mp1/<ver>/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
#     cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake ..
#
#   Mode B — Generic ARM hard-float cross-toolchain (Linaro / Debian):
#     cmake -B build \
#       -DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake \
#       -DCROSS_COMPILE=arm-linux-gnueabihf- \
#       ..
#
# ******************************************************************************

set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# -----------------------------------------------------------------------------
# Toolchain — Mode A (SDK) takes priority over Mode B (bare prefix)
# The OpenSTLinux SDK environment-setup script exports:
#   CC      = arm-ostl-linux-gnueabi-gcc --sysroot <path>
#   CXX     = arm-ostl-linux-gnueabi-g++ --sysroot <path>
#   LD      = arm-ostl-linux-gnueabi-ld
#   OECORE_TARGET_SYSROOT = <sysroot path>
# -----------------------------------------------------------------------------
if(DEFINED ENV{CC})
    # --- Mode A: SDK sets CC directly (may include --sysroot in the string) ---
    # CMake needs the compiler path without extra flags.
    # Extract the compiler executable (first token before any space).
    string(REGEX REPLACE " .*$" "" _cc_exec "$ENV{CC}")
    set(CMAKE_C_COMPILER "${_cc_exec}" CACHE FILEPATH "C compiler" FORCE)

    # Extract --sysroot=<path> from CC or CFLAGS (SDK exports both)
    if(NOT CMAKE_SYSROOT)
        foreach(_env_var CC CFLAGS)
            if(DEFINED ENV{${_env_var}})
                string(REGEX MATCH "--sysroot=([^ ]+)" _m "$ENV{${_env_var}}")
                if(_m)
                    string(REPLACE "--sysroot=" "" CMAKE_SYSROOT "${_m}")
                    break()
                endif()
            endif()
        endforeach()
    endif()

    # Fallback: OECORE_TARGET_SYSROOT set by SDK
    if(NOT CMAKE_SYSROOT AND DEFINED ENV{OECORE_TARGET_SYSROOT})
        set(CMAKE_SYSROOT "$ENV{OECORE_TARGET_SYSROOT}" CACHE PATH "" FORCE)
    endif()

    # Propagate PKG_CONFIG settings from SDK environment
    if(DEFINED ENV{PKG_CONFIG_PATH})
        set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}")
    endif()
    if(DEFINED ENV{PKG_CONFIG_SYSROOT_DIR})
        set(ENV{PKG_CONFIG_SYSROOT_DIR} "$ENV{PKG_CONFIG_SYSROOT_DIR}")
    endif()

else()
    # --- Mode B: bare cross-toolchain prefix ---
    set(CROSS_COMPILE "arm-linux-gnueabihf-"
        CACHE STRING "Cross-compiler prefix (e.g. arm-linux-gnueabihf-)")
    set(CMAKE_C_COMPILER   "${CROSS_COMPILE}gcc"     CACHE FILEPATH "" FORCE)
    set(CMAKE_AR           "${CROSS_COMPILE}ar"      CACHE FILEPATH "" FORCE)
    set(CMAKE_STRIP        "${CROSS_COMPILE}strip"   CACHE FILEPATH "" FORCE)
    set(CMAKE_OBJCOPY      "${CROSS_COMPILE}objcopy" CACHE FILEPATH "" FORCE)
    set(CMAKE_LINKER       "${CROSS_COMPILE}ld"      CACHE FILEPATH "" FORCE)
    set(CMAKE_RANLIB       "${CROSS_COMPILE}ranlib"  CACHE FILEPATH "" FORCE)
endif()

# -----------------------------------------------------------------------------
# CPU flags — Cortex-A7, NEON/VFPv4, hard-float
# These match the OpenSTLinux SDK tune:
#   cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
# -----------------------------------------------------------------------------
set(_MP1_ARCH
    "-mcpu=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard -mthumb"
)

# Append to any flags already set by the SDK CC string (which may carry -march)
# Use INIT cache variables so the user can still override with -DCMAKE_C_FLAGS=
set(CMAKE_C_FLAGS_INIT            "${_MP1_ARCH}" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_INIT   "" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_INIT "" CACHE STRING "" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS_INIT "" CACHE STRING "" FORCE)

# -----------------------------------------------------------------------------
# Sysroot search policy
# PROGRAM = host tools (cmake, pkg-config)  → NEVER (use host)
# LIBRARY / INCLUDE / PACKAGE              → ONLY  (use sysroot)
# -----------------------------------------------------------------------------
if(CMAKE_SYSROOT)
    message(STATUS "[stm32mp1-toolchain] sysroot: ${CMAKE_SYSROOT}")
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
else()
    message(STATUS "[stm32mp1-toolchain] no sysroot — Mode B (bare toolchain)")
    message(STATUS "  Ensure libraries are installed under the toolchain sysroot")
    message(STATUS "  or set CMAKE_SYSROOT manually.")
endif()
