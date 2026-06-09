# ******************************************************************************
# CMakeLists.txt — STSAFE Linux Middleware
# ******************************************************************************
#
# Supported devices:
#   STSAFE-A120  (NIST/Brainpool ECDSA sign + verify — provider: stsafea.so)
#   STSAFE-L010  (Ed25519 sign in HW, verify in SW — provider: stsafel.so)
#
# ──────────────────────────────────────────────────────────────────────────────
# Three build configurations
# ──────────────────────────────────────────────────────────────────────────────
#
#   ① STSAFE-A120 only
#       cmake -B build/stsafe-a \
#             [-DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake] \
#             -DTARGET_DEVICE=STSAFE_A \
#             -DDEPLOY_TARGET=root@<board-ip>
#       cmake --build build/stsafe-a
#       cmake --build build/stsafe-a --target deploy
#
#   ② STSAFE-L010 only
#       cmake -B build/stsafe-l \
#             [-DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake] \
#             -DTARGET_DEVICE=STSAFE_L \
#             -DDEPLOY_TARGET=root@<board-ip>
#       cmake --build build/stsafe-l
#       cmake --build build/stsafe-l --target deploy
#
#   ③ Both devices (TARGET_DEVICE=ALL, the default)
#       cmake -B build/all \
#             [-DCMAKE_TOOLCHAIN_FILE=cmake/stm32mp1-toolchain.cmake] \
#             -DDEPLOY_TARGET=root@<board-ip>
#       cmake --build build/all
#       cmake --build build/all --target deploy
#
#       In ALL mode, per-device example binaries land in sub-directories to
#       avoid name collisions (both products share example names like
#       "01_Echo_loop"):
#           build/all/stsafe-a/<binary>   ← STSAFE-A120 examples
#           build/all/stsafe-l/<binary>   ← STSAFE-L010 examples
#           build/all/<daemon|lib|*.so>   ← shared infrastructure
#
# ******************************************************************************

cmake_minimum_required(VERSION 3.18)

project(stse-linux
    VERSION   1.0.0
    LANGUAGES C
    DESCRIPTION
        "STSAFE Linux userspace middleware — \
privilege-separated I2C daemon, shared library, and OpenSSL 3.x providers"
)

# ============================================================================
# Options
# ============================================================================
option(BUILD_EXAMPLES  "Build all example programs"                              ON)
option(BUILD_PROVIDER  "Build OpenSSL 3.x providers (stsafea.so, stsafel.so)"  ON)
option(ENABLE_GTK_DEMO "Build 06_GTK_Authentication_Demo (requires gtk+-3.0)"   ON)

set(TARGET_DEVICE "ALL"
    CACHE STRING "Device profile: ALL | STSAFE_A (A120 only) | STSAFE_L (L010 only)")
set_property(CACHE TARGET_DEVICE PROPERTY STRINGS ALL STSAFE_A STSAFE_L)

set(DEPLOY_TARGET "root@stm32mp1"
    CACHE STRING "SSH destination for the 'deploy' custom target (user@host or user@ip)")

set(DEPLOY_EXAMPLES_DIR "/home/root/stse-linux"
    CACHE PATH
    "Remote base directory for deployed examples (stsafe-a/ and stsafe-l/ sub-dirs are created automatically)")

set(OPENSSL_MODULES_INSTALL_DIR ""
    CACHE PATH
    "Override provider .so install directory (empty = auto-detect via 'openssl version -a')")

# ============================================================================
# Resolve device build flags
# ============================================================================
if(TARGET_DEVICE STREQUAL "STSAFE_A" OR TARGET_DEVICE STREQUAL "ALL")
    set(BUILD_STSAFEA TRUE)
else()
    set(BUILD_STSAFEA FALSE)
endif()

if(TARGET_DEVICE STREQUAL "STSAFE_L" OR TARGET_DEVICE STREQUAL "ALL")
    set(BUILD_STSAFEL TRUE)
else()
    set(BUILD_STSAFEL FALSE)
endif()

if(NOT BUILD_STSAFEA AND NOT BUILD_STSAFEL)
    message(FATAL_ERROR
        "TARGET_DEVICE '${TARGET_DEVICE}' is not recognised.\n"
        "Valid values: ALL  STSAFE_A  STSAFE_L\n")
endif()

# ============================================================================
# Per-device binary output directories
#
# In ALL mode A120 and L010 examples share names (e.g. 01_Echo_loop).
# CMake target names keep the 'l010_' prefix for uniqueness; OUTPUT_NAME
# strips it so the on-disk binary has no prefix.  Binaries land in
# device-specific subdirectories inside CMAKE_BINARY_DIR.
#
# In single-device mode all output lands directly in CMAKE_BINARY_DIR.
# ============================================================================
if(TARGET_DEVICE STREQUAL "ALL")
    set(A120_BIN_DIR "${CMAKE_BINARY_DIR}/stsafe-a")
    set(L010_BIN_DIR "${CMAKE_BINARY_DIR}/stsafe-l")
else()
    set(A120_BIN_DIR "${CMAKE_BINARY_DIR}")
    set(L010_BIN_DIR "${CMAKE_BINARY_DIR}")
endif()

# ============================================================================
# Example name registries
# Defined here so both the build and the deploy sections can reference them.
# ============================================================================

# STSAFE-A120: CMake target name == binary output name (no prefix needed).
set(STSE_A120_STRUCTURED_EXAMPLES
    01_Echo_loop
    01_Hash
    01_Random_number
    01_Device_authentication
    01_Device_authentication_multi_steps
    01_Key_pair_generation_NIST_P256
    01_Key_pair_generation_NIST_P521
    01_Key_pair_generation_BRAINPOOL_P512
    01_Key_pair_generation_EDWARDS_25519
    01_Secure_data_storage_zone_access
    01_Secure_data_storage_counter_access
    02_Command_AC_provisioning
    02_Host_key_provisioning
    02_Host_key_provisioning_wrapped
    03_ECDH
    03_Key_wrapping
    04_Symmetric_key_provisioning_control_fields
    05_Symmetric_key_establishment_compute_AES-128_CMAC
    05_Symmetric_key_establishment_encrypt_AES-256_CCM
    05_Symmetric_key_provisioning_wrapped_compute_AES-128_CMAC
    05_Symmetric_key_provisioning_wrapped_encrypt_AES-256_CCM
)

# Full A120 binary name list (expanded further if GTK is found)
set(_a120_all_bin_names
    stse_echo_example
    stse_sign_example
    ${STSE_A120_STRUCTURED_EXAMPLES}
    02_OpenSSL_ecdsa_sign_verify
)

# STSAFE-L010: binary output names (no prefix) and CMake target names (l010_
# prefix kept for uniqueness when building ALL).
set(STSE_L010_EXAMPLE_BINARIES
    01_Echo_loop
    01_Device_authentication
    01_Device_authentication_multi_steps
    01_Secure_data_storage
    02_OpenSSL_eddsa_sign
)

set(STSE_L010_EXAMPLE_TARGETS
    l010_01_Echo_loop
    l010_01_Device_authentication
    l010_01_Device_authentication_multi_steps
    l010_01_Secure_data_storage
    l010_02_OpenSSL_eddsa_sign
)

# ============================================================================
# CMake module path and install layout
# ============================================================================
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(GNUInstallDirs)

# ============================================================================
# Global output directories (daemon, library, providers)
# Individual example targets override RUNTIME_OUTPUT_DIRECTORY below.
# ============================================================================
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# ============================================================================
# STSELib submodule sanity check
# ============================================================================
set(STSELIB_DIR       "${CMAKE_CURRENT_SOURCE_DIR}/lib/STSELib")
set(STSE_PLATFORM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/STSELib_Platform")

if(NOT EXISTS "${STSELIB_DIR}/stselib.h")
    message(FATAL_ERROR
        "\nSTSELib submodule is not initialised!\n"
        "  Run: git submodule update --init lib/STSELib\n"
        "  Then: cd lib/STSELib && git checkout remotes/origin/feature/pkcs11\n")
endif()

file(GLOB_RECURSE STSELIB_SRCS CONFIGURE_DEPENDS "${STSELIB_DIR}/*.c")
if(NOT STSELIB_SRCS)
    message(FATAL_ERROR "No .c files found under ${STSELIB_DIR} — check submodule init.")
endif()

# ============================================================================
# External dependencies
# ============================================================================
find_package(OpenSSL  REQUIRED)   # OpenSSL::SSL  OpenSSL::Crypto
find_package(Threads  REQUIRED)   # Threads::Threads
find_package(PkgConfig QUIET)     # For GTK3 and openssl MODULESDIR detection

# ============================================================================
# Common compile options
# ============================================================================
add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -O2 -g
)

# B2 fix: -fshort-enums changes the enum ABI and must only be applied to
# targets that include STSELib headers and pass enum values to STSELib
# functions.  It is intentionally NOT added globally so that se-daemon and
# any future non-STSELib targets are unaffected.
set(STSE_SHORT_ENUM_FLAG -fshort-enums)

# ============================================================================
# Common include directories (STSELib headers, platform headers)
# ============================================================================
set(STSE_COMMON_INCLUDES
    "${STSELIB_DIR}"
    "${STSELIB_DIR}/sal"
    "${STSE_PLATFORM_DIR}"
)

# ============================================================================
# TARGET 1: se-daemon
#   Minimal privileged I²C bus proxy.  No STSELib.  No OpenSSL.
# ============================================================================
add_executable(se-daemon daemon/se_daemon.c)
target_include_directories(se-daemon PRIVATE "${STSE_PLATFORM_DIR}")
target_link_libraries(se-daemon PRIVATE Threads::Threads)
install(TARGETS se-daemon RUNTIME DESTINATION "${CMAKE_INSTALL_SBINDIR}")
install(FILES daemon/se-daemon.service DESTINATION /etc/systemd/system)

# ============================================================================
# TARGET 2: libstse.so  (versioned shared library)
#   Full STSELib + IPC platform layer.  Application-facing API.
# ============================================================================
set(STSE_PLATFORM_SRCS
    "${STSE_PLATFORM_DIR}/stse_platform_i2c.c"
    "${STSE_PLATFORM_DIR}/stse_platform_delay.c"
    "${STSE_PLATFORM_DIR}/stse_platform_aes.c"
    "${STSE_PLATFORM_DIR}/stse_platform_ecc.c"
    "${STSE_PLATFORM_DIR}/stse_platform_hash.c"
    "${STSE_PLATFORM_DIR}/stse_platform_random.c"
    "${STSE_PLATFORM_DIR}/stse_platform_crc.c"
    "${STSE_PLATFORM_DIR}/stse_platform_crypto_init.c"
    "${STSE_PLATFORM_DIR}/stse_platform_power.c"
    "${STSE_PLATFORM_DIR}/stse_platform_st1wire.c"
)

add_library(stse SHARED ${STSELIB_SRCS} ${STSE_PLATFORM_SRCS})
set_target_properties(stse PROPERTIES
    OUTPUT_NAME stse
    VERSION     1.0      # libstse.so.1.0
    SOVERSION   1        # libstse.so.1 → libstse.so symlink
)
target_include_directories(stse PRIVATE ${STSE_COMMON_INCLUDES})
target_compile_options(stse PRIVATE ${STSE_SHORT_ENUM_FLAG})
target_link_libraries(stse PRIVATE
    OpenSSL::SSL OpenSSL::Crypto Threads::Threads m)
install(TARGETS stse
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    NAMELINK_COMPONENT development)

# ============================================================================
# Examples
# ============================================================================
if(BUILD_EXAMPLES)

    set(EXAMPLE_BUILD_RPATH   "${CMAKE_BINARY_DIR}")
    set(EXAMPLE_INSTALL_RPATH "${CMAKE_INSTALL_FULL_LIBDIR}")

    # ── STSAFE-A120 examples ──────────────────────────────────────────────
    if(BUILD_STSAFEA)

        add_library(apps_utils OBJECT
            examples/stsafe-a120/apps_utils/Apps_utils.c)
        target_include_directories(apps_utils PUBLIC
            ${STSE_COMMON_INCLUDES}
            "${CMAKE_CURRENT_SOURCE_DIR}/examples/stsafe-a120/apps_utils")
        target_compile_options(apps_utils PRIVATE ${STSE_SHORT_ENUM_FLAG})

        # Helper: register one STSAFE-A120 example.
        # Binary output goes to A120_BIN_DIR.
        function(stse_add_example target_name src_file use_apps_utils)
            if(use_apps_utils)
                add_executable(${target_name} "${src_file}"
                    $<TARGET_OBJECTS:apps_utils>)
            else()
                add_executable(${target_name} "${src_file}")
            endif()
            target_include_directories(${target_name} PRIVATE
                ${STSE_COMMON_INCLUDES}
                "${CMAKE_CURRENT_SOURCE_DIR}/examples/stsafe-a120/apps_utils")
            target_link_libraries(${target_name} PRIVATE
                stse OpenSSL::SSL OpenSSL::Crypto)
            target_compile_options(${target_name} PRIVATE ${STSE_SHORT_ENUM_FLAG})
            set_target_properties(${target_name} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY "${A120_BIN_DIR}"
                BUILD_RPATH              "${EXAMPLE_BUILD_RPATH}"
                INSTALL_RPATH            "${EXAMPLE_INSTALL_RPATH}")
            install(TARGETS ${target_name}
                RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
        endfunction()

        stse_add_example(stse_echo_example
            examples/stsafe-a120/stse_echo_example.c FALSE)
        stse_add_example(stse_sign_example
            examples/stsafe-a120/stse_sign_example.c FALSE)

        foreach(ex IN LISTS STSE_A120_STRUCTURED_EXAMPLES)
            set(_src "${CMAKE_CURRENT_SOURCE_DIR}/examples/stsafe-a120/${ex}/main.c")
            if(EXISTS "${_src}")
                stse_add_example(${ex} "${_src}" TRUE)
            else()
                message(WARNING "A120 example source not found, skipping: ${_src}")
            endif()
        endforeach()

        # GTK3 authentication demo (optional)
        if(ENABLE_GTK_DEMO AND PkgConfig_FOUND)
            pkg_check_modules(GTK3 QUIET gtk+-3.0)
            if(GTK3_FOUND)
                add_executable(06_GTK_Authentication_Demo
                    examples/stsafe-a120/06_GTK_Authentication_Demo/main.c
                    $<TARGET_OBJECTS:apps_utils>)
                target_include_directories(06_GTK_Authentication_Demo PRIVATE
                    ${STSE_COMMON_INCLUDES}
                    "${CMAKE_CURRENT_SOURCE_DIR}/examples/stsafe-a120/apps_utils"
                    ${GTK3_INCLUDE_DIRS})
                target_compile_options(06_GTK_Authentication_Demo PRIVATE
                    ${GTK3_CFLAGS_OTHER})
                target_link_libraries(06_GTK_Authentication_Demo PRIVATE
                    stse OpenSSL::SSL OpenSSL::Crypto
                    ${GTK3_LIBRARIES} Threads::Threads)
                set_target_properties(06_GTK_Authentication_Demo PROPERTIES
                    RUNTIME_OUTPUT_DIRECTORY "${A120_BIN_DIR}"
                    BUILD_RPATH              "${EXAMPLE_BUILD_RPATH}"
                    INSTALL_RPATH            "${EXAMPLE_INSTALL_RPATH}")
                install(TARGETS 06_GTK_Authentication_Demo
                    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
                # Register for deploy
                list(APPEND _a120_all_bin_names 06_GTK_Authentication_Demo)
                message(STATUS "[stse] GTK3 found — building 06_GTK_Authentication_Demo")
            else()
                message(STATUS "[stse] GTK3 not found — skipping 06_GTK_Authentication_Demo")
            endif()
        endif()

    endif() # BUILD_STSAFEA

    # ── STSAFE-L010 examples ──────────────────────────────────────────────
    if(BUILD_STSAFEL)

        add_library(apps_utils_l OBJECT
            examples/stsafe-l010/apps_utils/Apps_utils.c)
        target_include_directories(apps_utils_l PUBLIC
            ${STSE_COMMON_INCLUDES}
            "${CMAKE_CURRENT_SOURCE_DIR}/examples/stsafe-l010/apps_utils")
        target_compile_options(apps_utils_l PRIVATE ${STSE_SHORT_ENUM_FLAG})

        # Helper: register one STSAFE-L010 example.
        # target_name  — internal CMake name, keeps 'l010_' prefix in ALL mode
        # output_name  — on-disk binary name, no prefix
        # Binary output goes to L010_BIN_DIR.
        function(stsel_add_example target_name output_name src_file use_apps_utils)
            if(use_apps_utils)
                add_executable(${target_name} "${src_file}"
                    $<TARGET_OBJECTS:apps_utils_l>)
            else()
                add_executable(${target_name} "${src_file}")
            endif()
            target_include_directories(${target_name} PRIVATE
                ${STSE_COMMON_INCLUDES}
                "${CMAKE_CURRENT_SOURCE_DIR}/examples/stsafe-l010/apps_utils")
            target_link_libraries(${target_name} PRIVATE
                stse OpenSSL::SSL OpenSSL::Crypto)
            target_compile_options(${target_name} PRIVATE ${STSE_SHORT_ENUM_FLAG})
            set_target_properties(${target_name} PROPERTIES
                OUTPUT_NAME              "${output_name}"
                RUNTIME_OUTPUT_DIRECTORY "${L010_BIN_DIR}"
                BUILD_RPATH              "${EXAMPLE_BUILD_RPATH}"
                INSTALL_RPATH            "${EXAMPLE_INSTALL_RPATH}")
            install(TARGETS ${target_name}
                RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
        endfunction()

        stsel_add_example(l010_01_Echo_loop 01_Echo_loop
            "examples/stsafe-l010/01_Echo_loop/main.c" TRUE)
        stsel_add_example(l010_01_Device_authentication 01_Device_authentication
            "examples/stsafe-l010/01_Device_authentication/main.c" TRUE)
        stsel_add_example(l010_01_Device_authentication_multi_steps 01_Device_authentication_multi_steps
            "examples/stsafe-l010/01_Device_authentication_multi_steps/main.c" TRUE)
        stsel_add_example(l010_01_Secure_data_storage 01_Secure_data_storage
            "examples/stsafe-l010/01_Secure_data_storage/main.c" TRUE)

    endif() # BUILD_STSAFEL

endif() # BUILD_EXAMPLES

# ============================================================================
# Provider install directory
# Priority: user-supplied > auto-detected via 'openssl version -a' > fallback
# ============================================================================
if(OPENSSL_MODULES_INSTALL_DIR)
    set(STSE_PROV_DEST "${OPENSSL_MODULES_INSTALL_DIR}")
else()
    find_program(_OPENSSL_CMD NAMES openssl
        HINTS "${CMAKE_SYSROOT}/usr/bin" "${CMAKE_SYSROOT}/bin"
        NO_DEFAULT_PATH)
    if(NOT _OPENSSL_CMD)
        find_program(_OPENSSL_CMD NAMES openssl)
    endif()
    if(_OPENSSL_CMD)
        execute_process(
            COMMAND "${_OPENSSL_CMD}" version -a
            OUTPUT_VARIABLE _ossl_version_out
            ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(REGEX MATCH "MODULESDIR: \"([^\"]+)\"" _m "${_ossl_version_out}")
        if(_m)
            set(STSE_PROV_DEST "${CMAKE_MATCH_1}")
        endif()
    endif()
    if(NOT STSE_PROV_DEST)
        set(STSE_PROV_DEST "${CMAKE_INSTALL_FULL_LIBDIR}/ossl-modules")
    endif()
endif()
message(STATUS "[stse] Provider install directory: ${STSE_PROV_DEST}")

# ============================================================================
# TARGET: OpenSSL 3.x providers  (MODULE — loaded at runtime, not linked)
# ============================================================================
if(BUILD_PROVIDER)

    # ── stsafea.so — STSAFE-A120 (NIST/Brainpool ECDSA, hardware sign+verify)
    if(BUILD_STSAFEA)

        add_library(stsafea_provider MODULE providers/stsafea_provider.c)
        set_target_properties(stsafea_provider PROPERTIES
            OUTPUT_NAME stsafea PREFIX "" SUFFIX ".so"
            BUILD_RPATH   "${CMAKE_BINARY_DIR}"
            INSTALL_RPATH "${CMAKE_INSTALL_FULL_LIBDIR}")
        target_include_directories(stsafea_provider PRIVATE
            ${STSE_COMMON_INCLUDES}
            "${CMAKE_CURRENT_SOURCE_DIR}/providers")
        target_compile_options(stsafea_provider PRIVATE ${STSE_SHORT_ENUM_FLAG})
        target_link_libraries(stsafea_provider PRIVATE
            stse OpenSSL::SSL OpenSSL::Crypto)
        install(TARGETS stsafea_provider LIBRARY DESTINATION "${STSE_PROV_DEST}")

        # Provider demo: ECDSA sign + hardware verify
        add_executable(02_OpenSSL_ecdsa_sign_verify
            examples/stsafe-a120/02_OpenSSL_ecdsa_sign_verify/main.c)
        target_include_directories(02_OpenSSL_ecdsa_sign_verify PRIVATE
            ${STSE_COMMON_INCLUDES}
            "${CMAKE_CURRENT_SOURCE_DIR}/providers")
        target_link_libraries(02_OpenSSL_ecdsa_sign_verify PRIVATE
            OpenSSL::SSL OpenSSL::Crypto)
        set_target_properties(02_OpenSSL_ecdsa_sign_verify PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${A120_BIN_DIR}")
        install(TARGETS 02_OpenSSL_ecdsa_sign_verify
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

    endif() # BUILD_STSAFEA

    # ── stsafel.so — STSAFE-L010 (Ed25519 hardware sign, software verify)
    if(BUILD_STSAFEL)

        add_library(stsafel_provider MODULE providers/stsafel_provider.c)
        set_target_properties(stsafel_provider PROPERTIES
            OUTPUT_NAME stsafel PREFIX "" SUFFIX ".so"
            BUILD_RPATH   "${CMAKE_BINARY_DIR}"
            INSTALL_RPATH "${CMAKE_INSTALL_FULL_LIBDIR}")
        target_include_directories(stsafel_provider PRIVATE
            ${STSE_COMMON_INCLUDES}
            "${CMAKE_CURRENT_SOURCE_DIR}/providers")
        target_compile_options(stsafel_provider PRIVATE ${STSE_SHORT_ENUM_FLAG})
        target_link_libraries(stsafel_provider PRIVATE
            stse OpenSSL::SSL OpenSSL::Crypto)
        install(TARGETS stsafel_provider LIBRARY DESTINATION "${STSE_PROV_DEST}")

        # Provider demo: Ed25519 hardware sign + software verify
        # CMake target keeps 'l010_' prefix; binary output name has none.
        add_executable(l010_02_OpenSSL_eddsa_sign
            examples/stsafe-l010/02_OpenSSL_eddsa_sign/main.c)
        target_include_directories(l010_02_OpenSSL_eddsa_sign PRIVATE
            ${STSE_COMMON_INCLUDES}
            "${CMAKE_CURRENT_SOURCE_DIR}/providers")
        target_link_libraries(l010_02_OpenSSL_eddsa_sign PRIVATE
            stse OpenSSL::SSL OpenSSL::Crypto)
        set_target_properties(l010_02_OpenSSL_eddsa_sign PROPERTIES
            OUTPUT_NAME              "02_OpenSSL_eddsa_sign"
            RUNTIME_OUTPUT_DIRECTORY "${L010_BIN_DIR}")
        install(TARGETS l010_02_OpenSSL_eddsa_sign
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

    endif() # BUILD_STSAFEL

endif() # BUILD_PROVIDER

# ============================================================================
# Custom target: deploy
#
# Transfers se-daemon, libstse.so, providers and examples to the target board
# over SSH using cat-pipe (no scp/rsync required on the host).
# Examples are archived with tar for a single SSH connection per device.
#
# Usage:
#   cmake --build <build-dir> --target deploy
# ============================================================================
set(_prefix "${CMAKE_INSTALL_PREFIX}")

# ── Accumulate DEPENDS and COMMAND items ─────────────────────────────────────
set(_deploy_deps se-daemon stse)
set(_deploy_cmds)

# Helper macro — appends one COMMAND entry to _deploy_cmds
macro(_dcmd)
    list(APPEND _deploy_cmds COMMAND ${ARGN})
endmacro()

# Stop daemon on target (ignore failure if not running)
_dcmd(ssh "${DEPLOY_TARGET}" "systemctl stop se-daemon 2>/dev/null || true")

# Create all required remote directories up front
_dcmd(ssh "${DEPLOY_TARGET}"
    "mkdir -p '${_prefix}/sbin' '${_prefix}/lib' '/etc/systemd/system' '${DEPLOY_EXAMPLES_DIR}/stsafe-a' '${DEPLOY_EXAMPLES_DIR}/stsafe-l'")

# se-daemon (atomic swap to avoid partial writes)
_dcmd(sh -c
    "cat '${CMAKE_BINARY_DIR}/se-daemon' | ssh '${DEPLOY_TARGET}' \
     'cat > ${_prefix}/sbin/se-daemon.new && \
      chmod 0755 ${_prefix}/sbin/se-daemon.new && \
      mv -f ${_prefix}/sbin/se-daemon.new ${_prefix}/sbin/se-daemon'")

# libstse.so (with symlinks and ldconfig)
_dcmd(sh -c
    "cat '${CMAKE_BINARY_DIR}/libstse.so.1.0' | ssh '${DEPLOY_TARGET}' \
     'cat > ${_prefix}/lib/libstse.so.1.0 && \
      chmod 0755 ${_prefix}/lib/libstse.so.1.0 && \
      ln -sf libstse.so.1.0 ${_prefix}/lib/libstse.so.1 && \
      ln -sf libstse.so.1.0 ${_prefix}/lib/libstse.so && \
      ldconfig'")

# systemd service unit
_dcmd(sh -c
    "cat '${CMAKE_CURRENT_SOURCE_DIR}/daemon/se-daemon.service' | ssh '${DEPLOY_TARGET}' \
     'cat > /etc/systemd/system/se-daemon.service && \
      chmod 0644 /etc/systemd/system/se-daemon.service'")

# ── STSAFE-A120 — provider + examples ────────────────────────────────────────
if(BUILD_STSAFEA AND BUILD_PROVIDER)

    list(APPEND _deploy_deps stsafea_provider)
    if(TARGET 02_OpenSSL_ecdsa_sign_verify)
        list(APPEND _deploy_deps 02_OpenSSL_ecdsa_sign_verify)
    endif()

    # Add A120 example targets that were actually created
    foreach(_t stse_echo_example stse_sign_example
                ${STSE_A120_STRUCTURED_EXAMPLES}
                06_GTK_Authentication_Demo)
        if(TARGET "${_t}")
            list(APPEND _deploy_deps "${_t}")
        endif()
    endforeach()

    # Deploy stsafea.so provider
    _dcmd(ssh "${DEPLOY_TARGET}" "mkdir -p '${STSE_PROV_DEST}'")
    _dcmd(sh -c
        "cat '${CMAKE_BINARY_DIR}/stsafea.so' | ssh '${DEPLOY_TARGET}' \
         'cat > ${STSE_PROV_DEST}/stsafea.so && chmod 0755 ${STSE_PROV_DEST}/stsafea.so'")

    # Compute the list of A120 binaries that were actually built
    set(_a120_deploy_bins "")
    foreach(_b ${_a120_all_bin_names})
        if(TARGET "${_b}")
            list(APPEND _a120_deploy_bins "${_b}")
        endif()
    endforeach()

    if(_a120_deploy_bins)
        string(JOIN " " _a120_tar_list ${_a120_deploy_bins})
        # Transfer via tar (single SSH connection)
        _dcmd(sh -c
            "(cd '${A120_BIN_DIR}' && tar -cf - ${_a120_tar_list} 2>/dev/null) | \
             ssh '${DEPLOY_TARGET}' \
             \"mkdir -p '${DEPLOY_EXAMPLES_DIR}/stsafe-a' && \
               tar -xf - -C '${DEPLOY_EXAMPLES_DIR}/stsafe-a' && \
               chmod 0755 '${DEPLOY_EXAMPLES_DIR}/stsafe-a/'*\"")
    endif()

endif()

# ── STSAFE-L010 — provider + examples ────────────────────────────────────────
if(BUILD_STSAFEL AND BUILD_PROVIDER)

    list(APPEND _deploy_deps stsafel_provider)
    # Add L010 targets that were actually created
    foreach(_t IN LISTS STSE_L010_EXAMPLE_TARGETS)
        if(TARGET "${_t}")
            list(APPEND _deploy_deps "${_t}")
        endif()
    endforeach()

    # Deploy stsafel.so provider
    _dcmd(ssh "${DEPLOY_TARGET}" "mkdir -p '${STSE_PROV_DEST}'")
    _dcmd(sh -c
        "cat '${CMAKE_BINARY_DIR}/stsafel.so' | ssh '${DEPLOY_TARGET}' \
         'cat > ${STSE_PROV_DEST}/stsafel.so && chmod 0755 ${STSE_PROV_DEST}/stsafel.so'")

    # Compute list of L010 binary output names for built targets
    set(_l010_deploy_bins "")
    list(LENGTH STSE_L010_EXAMPLE_TARGETS _l010_count)
    math(EXPR _l010_last "${_l010_count} - 1")
    foreach(_i RANGE 0 ${_l010_last})
        list(GET STSE_L010_EXAMPLE_TARGETS  ${_i} _t)
        list(GET STSE_L010_EXAMPLE_BINARIES ${_i} _b)
        if(TARGET "${_t}")
            list(APPEND _l010_deploy_bins "${_b}")
        endif()
    endforeach()

    if(_l010_deploy_bins)
        string(JOIN " " _l010_tar_list ${_l010_deploy_bins})
        # Transfer via tar (single SSH connection)
        _dcmd(sh -c
            "(cd '${L010_BIN_DIR}' && tar -cf - ${_l010_tar_list} 2>/dev/null) | \
             ssh '${DEPLOY_TARGET}' \
             \"mkdir -p '${DEPLOY_EXAMPLES_DIR}/stsafe-l' && \
               tar -xf - -C '${DEPLOY_EXAMPLES_DIR}/stsafe-l' && \
               chmod 0755 '${DEPLOY_EXAMPLES_DIR}/stsafe-l/'*\"")
    endif()

endif()

# Enable and restart daemon
_dcmd(ssh "${DEPLOY_TARGET}"
    "systemctl daemon-reload && systemctl enable --now se-daemon")

# Assemble the final deploy target
add_custom_target(deploy
    DEPENDS ${_deploy_deps}
    COMMENT "Deploying to ${DEPLOY_TARGET}  (examples → ${DEPLOY_EXAMPLES_DIR})"
    ${_deploy_cmds}
    VERBATIM
)

# ============================================================================
# Status summary
# ============================================================================
message(STATUS "")
message(STATUS "=== STSAFE Linux build configuration ===")
message(STATUS "  Target device    : ${TARGET_DEVICE}")
message(STATUS "  Compiler         : ${CMAKE_C_COMPILER}")
if(CMAKE_SYSROOT)
    message(STATUS "  Sysroot          : ${CMAKE_SYSROOT}")
endif()
message(STATUS "  Build type       : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install prefix   : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  OpenSSL          : ${OPENSSL_VERSION} (${OPENSSL_INCLUDE_DIR})")
message(STATUS "  STSELib sources  : ${STSELIB_DIR}")
message(STATUS "  Build examples   : ${BUILD_EXAMPLES}")
message(STATUS "  Build providers  : ${BUILD_PROVIDER}")
if(BUILD_PROVIDER)
    message(STATUS "  Provider dir     : ${STSE_PROV_DEST}")
endif()
message(STATUS "  Deploy target    : ${DEPLOY_TARGET}")
message(STATUS "  Deploy examples  : ${DEPLOY_EXAMPLES_DIR}/stsafe-{a,l}/")
if(TARGET_DEVICE STREQUAL "ALL")
    message(STATUS "  A120 bin dir     : ${A120_BIN_DIR}")
    message(STATUS "  L010 bin dir     : ${L010_BIN_DIR}")
endif()
message(STATUS "=========================================")
message(STATUS "")
