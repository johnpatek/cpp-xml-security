cmake_minimum_required(VERSION 3.15)

project(cpp-xml-security)

find_package(Threads REQUIRED)
find_package(XercesC REQUIRED)
find_package(OpenSSL REQUIRED)

# Define variables that control feature detection
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckCXXSourceCompiles)

# Check for OpenSSL (adjust if necessary)
find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
  include_directories(${OPENSSL_INCLUDE_DIR})
  set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto OpenSSL::SSL)
  set(XSEC_HAVE_OPENSSL 1)
  set(XSEC_OPENSSL_HAVE_AES 1)
  set(XSEC_OPENSSL_HAVE_GCM 1)
  set(XSEC_OPENSSL_HAVE_EC 1)
  set(XSEC_OPENSSL_HAVE_SHA2 1)
else()
  set(XSEC_HAVE_OPENSSL 0)
  set(XSEC_OPENSSL_HAVE_AES 0)
  set(XSEC_OPENSSL_HAVE_GCM 0)
  set(XSEC_OPENSSL_cHAVE_EC 0)
  set(XSEC_OPENSSL_HAVE_SHA2 0)
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

set(CANON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/canon)
set(DSIG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/dsig)
set(ENC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/enc)
set(FRAMEWORK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/framework)
set(SAMPLES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/samples)
set(TRANSFORMERS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/transformers)
set(UTILS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/utils)
set(XENC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xsec/xenc)

# Add source files
file(GLOB XSEC_SOURCES ${CANON_DIR}/*.cpp ${DSIG_DIR}/*.cpp ${ENC_DIR}/*.cpp ${FRAMEWORK_DIR}/*.cpp ${TRANSFORMERS_DIR}/*.cpp ${UTILS_DIR}/*.cpp ${XENC_DIR}/*.cpp)

# Add libxml-security-c
add_library(xml-security-c SHARED ${XSEC_SOURCES})
target_link_libraries(xml-security-c ${XercesC_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} OpenSSL::Crypto OpenSSL::SSL)
target_include_directories(xml-security-c PUBLIC ${CANON_DIR}  ${XercesC_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})