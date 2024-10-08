#
# Copyright 2006-2010 The Apache Software Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Find generated headers in the build directory;
# find everything else in the source directory (always with full path)
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)

noinst_PROGRAMS = ${samples}
bin_PROGRAMS = ${tools}

AM_CXXFLAGS += $(xerces_CXXFLAGS)
LDADD = libxml-security-c.la $(xerces_LIBS)

#
# The following are sample programs.  They are NOT installed
#

samples =

# HMAC sign

samples += xsec-simpleHMAC
xsec_simpleHMAC_SOURCES = \
  samples/simpleHMAC.cpp \
  samples/IOStreamOutputter.cpp \
  samples/IOStreamOutputter.hpp

# HMAC validate

samples += xsec-simpleValidate
xsec_simpleValidate_SOURCES = \
  samples/simpleValidate.cpp \
  samples/IOStreamOutputter.cpp \
  samples/IOStreamOutputter.hpp

# Encrypt

samples += xsec-simpleEncrypt
xsec_simpleEncrypt_SOURCES = \
  samples/simpleEncrypt.cpp \
  samples/IOStreamOutputter.cpp \
  samples/IOStreamOutputter.hpp
xsec_simpleEncrypt_CXXFLAGS = $(AM_CXXFLAGS) \
  $(openssl_CFLAGS)
xsec_simpleEncrypt_LDADD = $(LDADD) \
  $(openssl_LIBS)

# Decrypt

samples += xsec-simpleDecrypt
xsec_simpleDecrypt_SOURCES = \
  samples/simpleDecrypt.cpp \
  samples/IOStreamOutputter.cpp \
  samples/IOStreamOutputter.hpp
xsec_simpleDecrypt_CXXFLAGS = $(AM_CXXFLAGS) \
  $(openssl_CFLAGS)
xsec_simpleDecrypt_LDADD = $(LDADD) \
  $(openssl_LIBS)

#
# Finally we compile the tools that can be used to manipulate
# XML Security inputs and outputs
#

tools =

# xtest

tools += xsec-xtest
xsec_xtest_SOURCES = \
   tools/xtest/xtest.cpp
xsec_xtest_CPPFLAGS = $(AM_CPPFLAGS) -DXSEC_BUILDING_TOOLS
xsec_xtest_CXXFLAGS = $(AM_CXXFLAGS) \
   $(openssl_CFLAGS)
xsec_xtest_LDADD = $(LDADD) \
   $(openssl_LIBS)

tools += xsec-c14n
xsec_c14n_SOURCES = \
   tools/c14n/c14n.cpp
xsec_c14n_CPPFLAGS = $(AM_CPPFLAGS) -DXSEC_BUILDING_TOOLS

tools += xsec-checksig
xsec_checksig_SOURCES = \
   tools/checksig/checksig.cpp \
   tools/checksig/AnonymousResolver.hpp \
   tools/checksig/AnonymousResolver.cpp \
   tools/checksig/InteropResolver.hpp \
   tools/checksig/InteropResolver.cpp
xsec_checksig_CPPFLAGS = $(AM_CPPFLAGS) -DXSEC_BUILDING_TOOLS
xsec_checksig_CXXFLAGS = $(AM_CXXFLAGS) \
   $(openssl_CFLAGS)
xsec_checksig_LDADD = $(LDADD) \
   $(openssl_LIBS)

tools += xsec-templatesign
xsec_templatesign_SOURCES = \
   tools/templatesign/templatesign.cpp
xsec_templatesign_CPPFLAGS = $(AM_CPPFLAGS) -DXSEC_BUILDING_TOOLS
xsec_templatesign_CXXFLAGS = $(AM_CXXFLAGS) \
   $(openssl_CFLAGS)
xsec_templatesign_LDADD = $(LDADD) \
   $(openssl_LIBS)

tools += xsec-txfmout
xsec_txfmout_SOURCES = \
   tools/txfmout/txfmout.cpp
xsec_txfmout_CPPFLAGS = $(AM_CPPFLAGS) -DXSEC_BUILDING_TOOLS

tools += xsec-siginf
xsec_siginf_SOURCES = \
   tools/siginf/siginf.cpp
xsec_siginf_CPPFLAGS = $(AM_CPPFLAGS) -DXSEC_BUILDING_TOOLS

tools += xsec-cipher
xsec_cipher_SOURCES = \
   tools/cipher/cipher.cpp \
   tools/cipher/XencInteropResolver.hpp \
   tools/cipher/XencInteropResolver.cpp
xsec_cipher_CPPFLAGS = $(AM_CPPFLAGS) -DXSEC_BUILDING_TOOLS
xsec_cipher_CXXFLAGS = $(AM_CXXFLAGS) \
   $(openssl_CFLAGS)
xsec_cipher_LDADD = $(LDADD) \
   $(openssl_LIBS)

libxml_security_c_la_CPPFLAGS = $(AM_CPPFLAGS) -DXSEC_BUILDING_LIBRARY

libxml_security_c_la_CXXFLAGS = \
   $(xerces_CXXFLAGS) \
   $(openssl_CFLAGS) \
   $(PTHREAD_CFLAGS)

libxml_security_c_la_LIBADD = \
   $(xerces_LIBS) \
   $(openssl_LIBS) \
   $(PTHREAD_LIBS)

lib_LTLIBRARIES = libxml-security-c.la

xsecincludedir = $(includedir)/xsec
canonincludedir = $(includedir)/xsec/canon
encincludedir = $(includedir)/xsec/enc
xscryptincludedir = $(includedir)/xsec/enc/XSCrypt
opensslincludedir = $(includedir)/xsec/enc/OpenSSL
dsigincludedir = $(includedir)/xsec/dsig
frameworkincludedir = $(includedir)/xsec/framework
transformersincludedir = $(includedir)/xsec/transformers
utilsincludedir = $(includedir)/xsec/utils
unixutilsincludedir = $(includedir)/xsec/utils/unixutils
xencincludedir = $(includedir)/xsec/xenc


# The required include files

#       A line like the following will generate a list of headers
#       for a given directory: (must be issued from base directory)
#
# find src/framework -name '*.hpp' -exec echo {} \\ ";" | sed "s/src/  xsec/g"

# Canon

canoninclude_HEADERS = \
  canon/XSECXMLNSStack.hpp \
  canon/XSECCanon.hpp \
  canon/XSECC14n20010315.hpp

# enc

encinclude_HEADERS = \
  enc/XSECCryptoKeyHMAC.hpp \
  enc/XSECCryptoX509.hpp \
  enc/XSECCryptoKeyDSA.hpp \
  enc/XSECCryptoKeyEC.hpp \
  enc/XSECKeyInfoResolver.hpp \
  enc/XSECCryptoHash.hpp \
  enc/XSECCryptoBase64.hpp \
  enc/XSECCryptoSymmetricKey.hpp \
  enc/XSECCryptoKey.hpp \
  enc/XSECCryptoProvider.hpp \
  enc/XSECKeyInfoResolverDefault.hpp \
  enc/XSECCryptoKeyRSA.hpp \
  enc/XSECCryptoException.hpp \
  enc/XSECCryptoUtils.hpp

xscryptinclude_HEADERS = \
  enc/XSCrypt/XSCryptCryptoBase64.hpp

opensslinclude_HEADERS = \
  enc/OpenSSL/OpenSSLCryptoBase64.hpp \
  enc/OpenSSL/OpenSSLCryptoSymmetricKey.hpp \
  enc/OpenSSL/OpenSSLCryptoProvider.hpp \
  enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp \
  enc/OpenSSL/OpenSSLCryptoX509.hpp \
  enc/OpenSSL/OpenSSLCryptoHashHMAC.hpp \
  enc/OpenSSL/OpenSSLCryptoKeyDSA.hpp \
  enc/OpenSSL/OpenSSLCryptoKeyEC.hpp \
  enc/OpenSSL/OpenSSLCryptoKeyHMAC.hpp \
  enc/OpenSSL/OpenSSLCryptoHash.hpp \
  enc/OpenSSL/OpenSSLSupport.hpp

dsiginclude_HEADERS = \
  dsig/DSIGKeyInfoSPKIData.hpp \
  dsig/DSIGAlgorithmHandlerDefault.hpp \
  dsig/DSIGXPathFilterExpr.hpp \
  dsig/DSIGKeyInfoX509.hpp \
  dsig/DSIGKeyInfoList.hpp \
  dsig/DSIGKeyInfoValue.hpp \
  dsig/DSIGKeyInfoDEREncoded.hpp \
  dsig/DSIGTransformC14n.hpp \
  dsig/DSIGTransformXSL.hpp \
  dsig/DSIGKeyInfo.hpp \
  dsig/DSIGKeyInfoPGPData.hpp \
  dsig/DSIGKeyInfoExt.hpp \
  dsig/DSIGObject.hpp \
  dsig/DSIGTransformList.hpp \
  dsig/DSIGTransform.hpp \
  dsig/DSIGTransformBase64.hpp \
  dsig/DSIGTransformXPath.hpp \
  dsig/DSIGKeyInfoMgmtData.hpp \
  dsig/DSIGSignedInfo.hpp \
  dsig/DSIGTransformXPathFilter.hpp \
  dsig/DSIGReferenceList.hpp \
  dsig/DSIGReference.hpp \
  dsig/DSIGSignature.hpp \
  dsig/DSIGKeyInfoName.hpp \
  dsig/DSIGTransformEnvelope.hpp \
  dsig/DSIGConstants.hpp

frameworkinclude_HEADERS = \
  framework/XSECAlgorithmHandler.hpp \
  framework/XSECURIResolver.hpp \
  framework/XSECDefs.hpp \
  framework/XSECEnv.hpp \
  framework/XSECException.hpp \
  framework/XSECError.hpp \
  framework/XSECProvider.hpp \
  framework/XSECURIResolverXerces.hpp \
  framework/XSECAlgorithmMapper.hpp \
  framework/XSECW32Config.hpp \
  framework/XSECVersion.hpp

nodist_frameworkinclude_HEADERS = \
  framework/XSECConfig.hpp

transformersinclude_HEADERS = \
  transformers/TXFMHash.hpp \
  transformers/TXFMParser.hpp \
  transformers/TXFMOutputFile.hpp \
  transformers/TXFMURL.hpp \
  transformers/TXFMBase.hpp \
  transformers/TXFMChar.hpp \
  transformers/TXFMCipher.hpp \
  transformers/TXFMEnvelope.hpp \
  transformers/TXFMChain.hpp \
  transformers/TXFMDocObject.hpp \
  transformers/TXFMConcatChains.hpp \
  transformers/TXFMSB.hpp \
  transformers/TXFMC14n.hpp \
  transformers/TXFMBase64.hpp

utilsinclude_HEADERS = \
  utils/XSECSafeBuffer.hpp \
  utils/XSECTXFMInputSource.hpp \
  utils/XSECNameSpaceExpander.hpp \
  utils/XSECXPathNodeList.hpp \
  utils/XSECSafeBufferFormatter.hpp \
  utils/XSECBinTXFMInputStream.hpp \
  utils/XSECPlatformUtils.hpp 

xencinclude_HEADERS = \
  xenc/XENCEncryptionMethod.hpp \
  xenc/XENCEncryptedType.hpp \
  xenc/XENCCipherData.hpp \
  xenc/XENCEncryptedKey.hpp \
  xenc/XENCCipherValue.hpp \
  xenc/XENCEncryptedData.hpp \
  xenc/XENCCipherReference.hpp \
  xenc/XENCCipher.hpp


libxml_security_c_la_SOURCES = ${lib_sources}

lib_sources =

# canon

lib_sources += ${canon_sources}

# Signature

lib_sources += ${dsig_sources}

# Main encryption sources

lib_sources += ${enc_sources}

# Framework sources

lib_sources += ${framework_sources}

# transformers

lib_sources += ${txfm_sources}

# Utility sources

lib_sources += ${utils_sources}

# XML Encryption

lib_sources += ${xenc_sources}

#
# The following blocks are conditionally added on the basis
# of selections made during the "configure" operation

if XSEC_AM_HAVE_OPENSSL
  lib_sources += ${openssl_sources}
endif

# Sources are build up using a find command:
#
# find xsec/transformers/ -name '*.cpp' -exec echo {} \\ ";" | sed "s/xsec\//  ..\/xsec\//g"

# canon

canon_sources = \
  canon/XSECC14n20010315.cpp \
  canon/XSECXMLNSStack.cpp \
  canon/XSECCanon.cpp

# Signature

dsig_sources = \
  dsig/DSIGKeyInfoPGPData.cpp \
  dsig/DSIGReferenceList.cpp \
  dsig/DSIGKeyInfoValue.cpp \
  dsig/DSIGKeyInfoDEREncoded.cpp \
  dsig/DSIGAlgorithmHandlerDefault.cpp \
  dsig/DSIGXPathFilterExpr.cpp \
  dsig/DSIGKeyInfoMgmtData.cpp \
  dsig/DSIGTransformXPathFilter.cpp \
  dsig/DSIGSignedInfo.cpp \
  dsig/DSIGKeyInfoList.cpp \
  dsig/DSIGConstants.cpp \
  dsig/DSIGSignature.cpp \
  dsig/DSIGTransformXSL.cpp \
  dsig/DSIGObject.cpp \
  dsig/DSIGTransformXPath.cpp \
  dsig/DSIGTransformEnvelope.cpp \
  dsig/DSIGKeyInfoName.cpp \
  dsig/DSIGTransformBase64.cpp \
  dsig/DSIGReference.cpp \
  dsig/DSIGKeyInfoSPKIData.cpp \
  dsig/DSIGTransformList.cpp \
  dsig/DSIGKeyInfoX509.cpp \
  dsig/DSIGKeyInfoExt.cpp \
  dsig/DSIGTransform.cpp \
  dsig/DSIGTransformC14n.cpp

# Main Crypto interface routines

enc_sources = \
  enc/XSECCryptoX509.cpp \
  enc/XSECKeyInfoResolverDefault.cpp \
  enc/XSECCryptoUtils.cpp \
  enc/XSECCryptoBase64.cpp \
  enc/XSCrypt/XSCryptCryptoBase64.cpp \
  enc/XSECCryptoException.cpp

# Framework files

framework_sources = \
  framework/XSECError.cpp \
  framework/XSECAlgorithmMapper.cpp \
  framework/XSECEnv.cpp \
  framework/XSECProvider.cpp \
  framework/XSECException.cpp \
  framework/XSECURIResolverXerces.cpp

txfm_sources = \
  transformers/TXFMBase.cpp \
  transformers/TXFMChain.cpp \
  transformers/TXFMCipher.cpp \
  transformers/TXFMParser.cpp \
  transformers/TXFMSB.cpp \
  transformers/TXFMEnvelope.cpp \
  transformers/TXFMBase64.cpp \
  transformers/TXFMHash.cpp \
  transformers/TXFMC14n.cpp \
  transformers/TXFMURL.cpp \
  transformers/TXFMOutputFile.cpp \
  transformers/TXFMDocObject.cpp \
  transformers/TXFMConcatChains.cpp \
  transformers/TXFMChar.cpp

# Utility files.  Note we don't worry about checking
# if the UNIX stuff is necessary - we just assume that
# we are running on a *NIX system because compiling under
# make.  Cygwin compiles use the UNIX utilities, not windows

utils_sources = \
  utils/XSECAlgorithmSupport.hpp \
  utils/XSECAlgorithmSupport.cpp \
  utils/XSECAutoPtr.hpp \
  utils/XSECBinTXFMInputStream.cpp \
  utils/XSECXPathNodeList.cpp \
  utils/XSECSafeBuffer.cpp \
  utils/XSECTXFMInputSource.cpp \
  utils/XSECDOMUtils.hpp \
  utils/XSECDOMUtils.cpp \
  utils/XSECSafeBufferFormatter.cpp \
  utils/XSECNameSpaceExpander.cpp \
  utils/XSECPlatformUtils.cpp

# XML Encryption

xenc_sources = \
  xenc/impl/XENCCipherReferenceImpl.cpp \
  xenc/impl/XENCEncryptionMethodImpl.cpp \
  xenc/impl/XENCEncryptedKeyImpl.hpp \
  xenc/impl/XENCCipherValueImpl.cpp \
  xenc/impl/XENCCipherImpl.hpp \
  xenc/impl/XENCAlgorithmHandlerDefault.hpp \
  xenc/impl/XENCCipherDataImpl.hpp \
  xenc/impl/XENCEncryptionMethodImpl.hpp \
  xenc/impl/XENCAlgorithmHandlerDefault.cpp \
  xenc/impl/XENCEncryptedDataImpl.cpp \
  xenc/impl/XENCEncryptedTypeImpl.hpp \
  xenc/impl/XENCCipherDataImpl.cpp \
  xenc/impl/XENCEncryptedDataImpl.hpp \
  xenc/impl/XENCCipherValueImpl.hpp \
  xenc/impl/XENCEncryptedTypeImpl.cpp \
  xenc/impl/XENCCipherImpl.cpp \
  xenc/impl/XENCEncryptedKeyImpl.cpp \
  xenc/impl/XENCCipherReferenceImpl.hpp

# Conditional crypto routines

openssl_sources = \
  enc/OpenSSL/OpenSSLCryptoHashHMAC.cpp \
  enc/OpenSSL/OpenSSLCryptoKeyRSA.cpp \
  enc/OpenSSL/OpenSSLCryptoHash.cpp \
  enc/OpenSSL/OpenSSLCryptoProvider.cpp \
  enc/OpenSSL/OpenSSLCryptoX509.cpp \
  enc/OpenSSL/OpenSSLCryptoBase64.cpp \
  enc/OpenSSL/OpenSSLCryptoKeyDSA.cpp \
  enc/OpenSSL/OpenSSLCryptoKeyEC.cpp \
  enc/OpenSSL/OpenSSLCryptoSymmetricKey.cpp \
  enc/OpenSSL/OpenSSLCryptoKeyHMAC.cpp \
  enc/OpenSSL/OpenSSLSupport.cpp

#
# Now the library specific build items
#
libxml_security_c_la_LDFLAGS = -version-info 30:0:0

