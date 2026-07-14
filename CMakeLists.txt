cmake_minimum_required(VERSION 3.22)

#
# This file is generated only once,
# and is not re-generated if converter is called multiple times.
#
# User is free to modify the file as much as necessary
#

# Setup compiler settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)


# Define the build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# Set the project name
set(CMAKE_PROJECT_NAME secureboot)

# Enable compile command to ease indexing with e.g. clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

# Core project settings
project(${CMAKE_PROJECT_NAME})
message("Build type: " ${CMAKE_BUILD_TYPE})

option(BOOT_ENABLE_RTT_LOG "Enable SEGGER RTT debug logging" ON)

# Enable CMake support for ASM and C languages
enable_language(C ASM)

# Create an executable object type
add_executable(${CMAKE_PROJECT_NAME})

# Add STM32CubeMX generated sources
add_subdirectory(cmake/stm32cubemx)

# Link directories setup
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user defined library search paths
)

# Add sources to executable
target_sources(${CMAKE_PROJECT_NAME} PRIVATE
    Core/Src/main.c
    Core/Src/com/crc16.c
    Core/Src/log/log.c
    Core/Src/com/my_packer.c
    Core/Src/com/packer.c
    Core/Src/com/comm_manager.c
    Core/Src/com/my_queue.c
    Core/Src/secure/sha256.c
    Core/Src/secure/crypto_util.c
    Core/Src/secure/crypto_manager.c
    Core/Src/secure/ecdsa_p256.c
    Core/Src/platform/boot_platform_stm32.c
    Core/Src/utils/custom_timer.c
    Core/Src/secure_boot.c
    Core/Src/secure/secure_boot_public_key.c
    Core/Src/com/boot_uart_protocol.c
    Core/Src/flash/boot_flash.c
    Core/Src/boot_controller.c
    # Add user sources here
)

if(BOOT_ENABLE_RTT_LOG)
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        Core/Src/log/SEGGER_RTT.c
    )
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
        LOG_ENABLE
    )
endif()

# Add include paths
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    Core/Inc
    Core/Inc/com
    Core/Inc/secure
    Core/Inc/log
    Core/Inc/platform
    Core/Inc/utils
    # Add user defined include paths
)

# Add project symbols (macros)
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user defined symbols
)

# Remove wrong libob.a library dependency when using cpp files
list(REMOVE_ITEM CMAKE_C_IMPLICIT_LINK_LIBRARIES ob)

# Add linked libraries
target_link_libraries(${CMAKE_PROJECT_NAME}
    stm32cubemx

    # Add user defined libraries
)
