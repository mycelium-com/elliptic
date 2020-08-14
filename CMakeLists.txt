cmake_minimum_required(VERSION 3.9)
project(elliptic VERSION 1.0.0 DESCRIPTION "Crypto primitives abstraction library")

# Crypto primitives
add_subdirectory(extras/hashing)
add_subdirectory(extras/ed25519)
add_subdirectory(extras/secp256k1)

set(elliptic_src
   src/sign.c
   src/keypair.c
   src/verify.c
   src/keychain.c
)

add_library(elliptic ${elliptic_src})

target_include_directories(elliptic PRIVATE include)
target_include_directories(elliptic PRIVATE extras/hashing/include)
target_include_directories(elliptic PRIVATE extras/ed25519/include)
target_include_directories(elliptic PRIVATE extras/secp256k1/include)

set_target_properties(elliptic PROPERTIES
   VERSION ${PROJECT_VERSION}
   POSITION_INDEPENDENT_CODE 1
   PUBLIC_HEADER "include/elliptic.h"
)

include(GNUInstallDirs)
install(TARGETS elliptic
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(elliptic.pc.in elliptic.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/elliptic.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
