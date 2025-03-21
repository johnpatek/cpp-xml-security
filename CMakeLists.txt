cmake_minimum_required(VERSION 3.15)

project(cpp-xml-security)

find_package(Threads REQUIRED)
find_package(XercesC REQUIRED)
find_package(OpenSSL REQUIRED)

# Define variables that control feature detection
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckCXXSourceCompiles)


if(NOT WIN32)
  if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto OpenSSL::SSL)
    set(XSEC_HAVE_OPENSSL 1)
    set(XSEC_OPENSSL_HAVE_AES 1)
    set(XSEC_OPENSSL_HAVE_GCM 1)
    set(XSEC_OPENSSL_HAVE_EC 1)
    set(XSEC_OPENSSL_HAVE_SHA2 1)
    set(XSEC_OPENSSL_HAVE_MGF1 1)
  else()
    set(XSEC_HAVE_OPENSSL 0)
    set(XSEC_OPENSSL_HAVE_AES 0)
    set(XSEC_OPENSSL_HAVE_GCM 0)
    set(XSEC_OPENSSL_cHAVE_EC 0)
    set(XSEC_OPENSSL_HAVE_SHA2 0)
    set(XSEC_OPENSSL_HAVE_MGF1 0)
  endif()

  # Check for getcwd(NULL, 0)
  check_symbol_exists(getcwd "unistd.h" XSEC_HAVE_GETCWD_DYN)

  # Check for EVP_CIPHER_CTX_set_padding
  check_symbol_exists(EVP_CIPHER_CTX_set_padding "openssl/evp.h" XSEC_OPENSSL_CANSET_PADDING)

  # Check if OpenSSL has const input buffers
  check_symbol_exists(X509_get_serialNumber "openssl/x509.h" XSEC_OPENSSL_CONST_BUFFERS)
  check_symbol_exists(d2i_X509 "openssl/x509.h" XSEC_OPENSSL_D2IX509_CONST_BUFFER)

  # Check if OpenSSL has CRYPTO_cleanup_all_ex_data
  check_symbol_exists(CRYPTO_cleanup_all_ex_data "openssl/crypto.h" XSEC_OPENSSL_HAVE_CRYPTO_CLEANUP_ALL_EX_DATA)

  # Generate the configured header
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/xsec/framework/XSECConfig.hpp.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/xsec/framework/XSECConfig.hpp
  )

  # Ensure the generated header is in the include path
  include_directories(${CMAKE_CURRENT_BINARY_DIR}/xsec/framework)
endif()

set(CANON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/canon)
set(DSIG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/dsig)
set(ENC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/enc)
set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/enc/OpenSSL)
set(XSCRYPT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/enc/XSCrypt)
set(FRAMEWORK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/framework)
set(SAMPLES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/samples)
set(TOOLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/tools)
set(TRANSFORMERS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/transformers)
set(UTILS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/utils)
set(XENC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/xenc)
set(IMPL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/xenc/impl)

# Add source files
file(
  GLOB 
  XSEC_SOURCES 
  ${CANON_DIR}/*.cpp ${DSIG_DIR}/*.cpp ${ENC_DIR}/*.cpp ${OPENSSL_DIR}/*.cpp ${XSCRYPT_DIR}/*.cpp ${FRAMEWORK_DIR}/*.cpp ${TRANSFORMERS_DIR}/*.cpp ${UTILS_DIR}/*.cpp ${XENC_DIR}/*.cpp ${IMPL_DIR}/*.cpp)

message(STATUS "xerces library: ${XercesC_LIBRARY}")
# Add libxml-security-c
if(WIN32)
  add_library(xml-security-c-static STATIC ${XSEC_SOURCES})
  add_library(xml-security-c-dynamic SHARED ${XSEC_SOURCES})
  target_include_directories(
    xml-security-c-static
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR} 
    ${XercesC_INCLUDE_DIRS} 
    ${OPENSSL_INCLUDE_DIR})
  target_include_directories(
    xml-security-c-dynamic
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR} 
    ${XercesC_INCLUDE_DIRS} 
    ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(xml-security-c-static PUBLIC ${XercesC_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} OpenSSL::Crypto OpenSSL::SSL)  
  target_link_libraries(xml-security-c-dynamic PUBLIC ${XercesC_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} OpenSSL::Crypto OpenSSL::SSL)  
  set_target_properties(xml-security-c-static PROPERTIES OUTPUT_NAME xml-security-c)
  set_target_properties(xml-security-c-dynamic PROPERTIES OUTPUT_NAME xml-security-c)
else()
  add_library(xml-security-c SHARED ${XSEC_SOURCES})
  target_include_directories(
    xml-security-c 
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR} 
    ${XercesC_INCLUDE_DIRS} 
    ${OPENSSL_INCLUDE_DIR})
  target_link_libraries(xml-security-c PUBLIC ${XercesC_LIBRARY} ${CMAKE_THREAD_LIBS_INIT} OpenSSL::Crypto OpenSSL::SSL)  
endif()

if(OPENSSL_FOUND)
  if(WIN32)
    target_compile_definitions(xml-security-c-static PUBLIC XSEC_HAVE_OPENSSL=1 XSEC_BUILDING_LIBRARY=1)
    target_compile_definitions(xml-security-c-dynamic PUBLIC XSEC_HAVE_OPENSSL=1 XSEC_BUILDING_LIBRARY=1)
  else()
    target_compile_definitions(xml-security-c PUBLIC XSEC_HAVE_OPENSSL=1 XSEC_OPENSSL_HAVE_AES=1 XSEC_OPENSSL_HAVE_GCM=1 XSEC_OPENSSL_HAVE_EC=1 XSEC_OPENSSL_HAVE_SHA2=1 XSEC_OPENSSL_HAVE_MGF1=1)
  endif()
endif()

add_executable(xsec-xtest ${TOOLS_DIR}/xtest/xtest.cpp)
if(WIN32)
  target_link_libraries(xsec-xtest xml-security-c-static)
else()
  target_link_libraries(xsec-xtest xml-security-c)
endif()