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
   src/bip32/secp256k1-hd.c
)

add_library(elliptic ${elliptic_src})

target_include_directories(elliptic PRIVATE include)
target_include_directories(elliptic PRIVATE src/bip32)
target_include_directories(elliptic PRIVATE extras/hashing/include)
target_include_directories(elliptic PRIVATE extras/ed25519/include)
target_include_directories(elliptic PRIVATE extras/secp256k1/include)

set_target_properties(elliptic PROPERTIES
   VERSION ${PROJECT_VERSION}
   POSITION_INDEPENDENT_CODE 1
   PUBLIC_HEADER "include/elliptic.h"
)

add_executable(test_sign_ed25519 misc/test_sign_ed25519.c $<TARGET_OBJECTS:elliptic>)
add_executable(test_sign_secp256k1 misc/test_sign_secp256k1.c $<TARGET_OBJECTS:elliptic>)
add_executable(test_hd_ed25519 misc/test_hd_ed25519.c $<TARGET_OBJECTS:elliptic>)
add_executable(test_hd_secp256k1 misc/test_hd_secp256k1.c $<TARGET_OBJECTS:elliptic>)

target_include_directories(test_sign_ed25519 PRIVATE include)
target_include_directories(test_sign_secp256k1 PRIVATE include)
target_include_directories(test_hd_ed25519 PRIVATE include)
target_include_directories(test_hd_secp256k1 PRIVATE include)

target_link_libraries(test_sign_ed25519 elliptic hashing ed25519 secp256k1)
target_link_libraries(test_sign_secp256k1 elliptic hashing ed25519 secp256k1)
target_link_libraries(test_hd_ed25519 elliptic hashing ed25519 secp256k1)
target_link_libraries(test_hd_secp256k1 elliptic hashing ed25519 secp256k1)

include(GNUInstallDirs)
install(TARGETS elliptic
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_file(elliptic.pc.in elliptic.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/elliptic.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
