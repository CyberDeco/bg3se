cmake_minimum_required(VERSION 3.16)
project(bg3se_macos VERSION 0.0.1 LANGUAGES C CXX)
set(CMAKE_OSX_ARCHITECTURES "arm64")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Example: send all built libs to their respective build dirs
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(FETCHCONTENT_BASE_DIR ${CMAKE_SOURCE_DIR}/External)

if(APPLE)
    # Ensure Homebrew paths are considered for finding packages like LLVM
    list(APPEND CMAKE_PREFIX_PATH /opt/homebrew /usr/local)
endif()

include(FetchContent)

# Include headers for your project's own headers
include_directories(include)

# --- External Dependencies managed by FetchContent ---

# fishhook - MacOS dynamic linker ? not sure if still necessary tbh
FetchContent_Declare(
    fishhook
    GIT_REPOSITORY https://github.com/facebook/fishhook.git
    GIT_TAG aadc161ac3b80db07a9908851839a17ba63a9eb1
)

# Also don't know if this is still necessary
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 10.1.1
)

FetchContent_Declare(
    glm
    GIT_REPOSITORY https://github.com/g-truc/glm.git
    GIT_TAG 0.9.9.6
)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.90.9
)

FetchContent_Declare(
    lua
    URL https://www.lua.org/ftp/lua-5.3.6.tar.gz
    URL_HASH SHA256=fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60
)

FetchContent_Declare(
    tinycrypt
    GIT_REPOSITORY https://github.com/intel/tinycrypt.git
    GIT_TAG b1fed54ce0f79e0e2ffbec7684bb4988a5f20607
)

# Make all declared FetchContent projects available (excluding nlohmann_json as it's downloaded separately)
FetchContent_MakeAvailable(fishhook fmt imgui lua tinycrypt)

# --- Download nlohmann/json (only json.hpp) ---
# Define the destination path for json.hpp
set(NLOHMANN_JSON_EXTERNAL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/External/nlohmann_json)
set(NLOHMANN_JSON_INCLUDE_DIR ${NLOHMANN_JSON_EXTERNAL_DIR}/include)
set(JSON_HPP_PATH ${NLOHMANN_JSON_INCLUDE_DIR}/json.hpp)

# Use a specific version URL for stability and to get only the header
set(JSON_HPP_URL "https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp")

# Create the directory if it doesn't exist
file(MAKE_DIRECTORY ${NLOHMANN_JSON_INCLUDE_DIR})

# Download json.hpp if it doesn't already exist
if(NOT EXISTS ${JSON_HPP_PATH})
    message(STATUS "Downloading json.hpp to ${JSON_HPP_PATH}")
    file(DOWNLOAD ${JSON_HPP_URL} ${JSON_HPP_PATH}
         STATUS download_status
         LOG download_log
         SHOW_PROGRESS)

    if(NOT download_status EQUAL 0)
        message(FATAL_ERROR "Failed to download json.hpp: ${download_log}")
    else()
        message(STATUS "Successfully downloaded json.hpp")
    endif()
else()
    message(STATUS "json.hpp already exists at ${JSON_HPP_PATH}, skipping download.")
endif()


# --- Configure fetched libraries ---

# GLM
FetchContent_Populate(glm) # Populate glm, as it's not made available via MakeAvailable for custom interface library
add_library(glm INTERFACE)
target_include_directories(glm INTERFACE ${glm_SOURCE_DIR})

# Lua
add_library(lua STATIC
    ${lua_SOURCE_DIR}/src/lapi.c
    ${lua_SOURCE_DIR}/src/lcode.c
    ${lua_SOURCE_DIR}/src/lctype.c
    ${lua_SOURCE_DIR}/src/ldebug.c
    ${lua_SOURCE_DIR}/src/ldo.c
    ${lua_SOURCE_DIR}/src/ldump.c
    ${lua_SOURCE_DIR}/src/lfunc.c
    ${lua_SOURCE_DIR}/src/lgc.c
    ${lua_SOURCE_DIR}/src/llex.c
    ${lua_SOURCE_DIR}/src/lmem.c
    ${lua_SOURCE_DIR}/src/lobject.c
    ${lua_SOURCE_DIR}/src/lopcodes.c
    ${lua_SOURCE_DIR}/src/lparser.c
    ${lua_SOURCE_DIR}/src/lstate.c
    ${lua_SOURCE_DIR}/src/lstring.c
    ${lua_SOURCE_DIR}/src/ltable.c
    ${lua_SOURCE_DIR}/src/ltm.c
    ${lua_SOURCE_DIR}/src/lundump.c
    ${lua_SOURCE_DIR}/src/lvm.c
    ${lua_SOURCE_DIR}/src/lzio.c
    ${lua_SOURCE_DIR}/src/lauxlib.c
    ${lua_SOURCE_DIR}/src/lbaselib.c
    ${lua_SOURCE_DIR}/src/lbitlib.c
    ${lua_SOURCE_DIR}/src/lcorolib.c
    ${lua_SOURCE_DIR}/src/ldblib.c
    ${lua_SOURCE_DIR}/src/liolib.c
    ${lua_SOURCE_DIR}/src/lmathlib.c
    ${lua_SOURCE_DIR}/src/loslib.c
    ${lua_SOURCE_DIR}/src/lstrlib.c
    ${lua_SOURCE_DIR}/src/ltablib.c
    ${lua_SOURCE_DIR}/src/loadlib.c
    ${lua_SOURCE_DIR}/src/linit.c
)
target_include_directories(lua PUBLIC ${lua_SOURCE_DIR})

# ImGui
add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
)
target_include_directories(imgui PUBLIC ${imgui_SOURCE_DIR})

# TinyCrypt
add_library(tinycrypt STATIC
    ${tinycrypt_SOURCE_DIR}/lib/source/aes_decrypt.c
    ${tinycrypt_SOURCE_DIR}/lib/source/aes_encrypt.c
    ${tinycrypt_SOURCE_DIR}/lib/source/ctr_mode.c
    ${tinycrypt_SOURCE_DIR}/lib/source/cbc_mode.c
    ${tinycrypt_SOURCE_DIR}/lib/source/sha256.c
    ${tinycrypt_SOURCE_DIR}/lib/source/hmac.c
    ${tinycrypt_SOURCE_DIR}/lib/source/utils.c
)
target_include_directories(tinycrypt PUBLIC ${tinycrypt_SOURCE_DIR}/lib/include)

# --- System packages ---
find_package(PkgConfig REQUIRED)
# jsoncpp is kept as it might be used by other parts of your project.
# Remove this line if you are certain your entire project will exclusively use nlohmann/json.
find_package(jsoncpp REQUIRED)
find_package(protobuf REQUIRED)
find_package(ZLIB REQUIRED)
find_package(CURL REQUIRED)
find_package(SDL2 REQUIRED)
find_package(Vulkan REQUIRED)

# --- Find LLVM ---
# This will try to find LLVMConfig.cmake, making the LLVM dependency portable.
find_package(LLVM REQUIRED CONFIG)

# Gather sources
file(GLOB_RECURSE PROJECT_SRC CONFIGURE_DEPENDS
    SetupScripts/*.cpp
    #BG3Extender/*.cpp
    #BG3Udater/*.cpp
    #CoreLib/*.cpp
    #CrashReporter/*.cpp
    #Docs/*.cpp
    #LuaDebugger/*.cpp
    #ResourceBundler/*.cpp
    #SymbolTableGenerator/*.cpp  # Ensure your VTableScanner.cpp is included here if it's part of this project
    #UpdateSigner/*.cpp
)

# Remove unwanted files like Jupyter checkpoint garbage
list(FILTER PROJECT_SRC EXCLUDE REGEX "\\.ipynb_checkpoints/")

# Shared library (MacOS .dylib) because Script Extender
add_library(bg3se_macos SHARED ${PROJECT_SRC})

# Ensure proper output file extension and name
set_target_properties(bg3se_macos PROPERTIES
    OUTPUT_NAME "bg3se_macos"
    SUFFIX ".dylib"
    INSTALL_NAME_DIR "@rpath"
)

# --- Link everything ---
target_link_libraries(bg3se_macos PRIVATE
    lua
    glm
    fmt::fmt
    imgui
    ${JSONCPP_LIBRARIES} # Keep if still using jsoncpp elsewhere
    ${Protobuf_LIBRARIES}
    tinycrypt
    ZLIB::ZLIB
    CURL::libcurl
    SDL2::SDL2
    Vulkan::Vulkan
    ${LLVM_LIBRARIES} # Use libraries found by find_package(LLVM)
)

# --- Add LLVM and nlohmann/json include directories ---
target_include_directories(bg3se_macos PRIVATE
    include
    ${Protobuf_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
    ${JSONCPP_INCLUDE_DIRS} # Keep if still using jsoncpp elsewhere
    ${LLVM_INCLUDE_DIRS} # Use include directories found by find_package(LLVM)
    ${NLOHMANN_JSON_INCLUDE_DIR} # nlohmann/json include directory (only json.hpp)
)

# --- Add RPATH for LLVM on macOS ---
# This helps the dynamic linker find LLVM libraries at runtime.
# We extract the directory from the first LLVM library found.
if(APPLE)
    if(LLVM_LIBRARIES)
        list(GET LLVM_LIBRARIES 0 _first_llvm_lib)
        get_filename_component(LLVM_LIB_PATH ${_first_llvm_lib} DIRECTORY)
        target_link_options(bg3se_macos PUBLIC
            "-Wl,-rpath,${LLVM_LIB_PATH}"
        )
    else()
        message(WARNING "LLVM_LIBRARIES not found, cannot set RPATH for LLVM.")
    endif()
endif()

# Optional: Add install rule for deployment
install(TARGETS bg3se_macos DESTINATION bin)