# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

# Process this file with autoreconf
AC_PREREQ(2.50)
AC_INIT([[XML-Security-C]],[3.0.0],[dev@shibboleth.net],[xml-security-c])
AC_CONFIG_SRCDIR(xsec)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE([foreign dist-bzip2 dist-zip subdir-objects nostdinc])
PKG_INSTALLDIR

AC_SYS_LARGEFILE

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[Produce debug variant (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    AM_CFLAGS="-D_DEBUG"
    AM_CXXFLAGS="-D_DEBUG"
fi


# Define the files we wish to generate

AC_CONFIG_FILES([Makefile xsec/Makefile xml-security-c.pc])
AC_CONFIG_HEADERS([config.h xsec/framework/XSECConfig.hpp])
AH_BOTTOM([#include <xsec/framework/XSECVersion.hpp>])

# Check for basic programs

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])
LT_INIT([disable-static])
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_AWK
AC_CHECK_PROG(AUTOCONF, autoconf, autoconf, true)

if test "$GCC" = "yes" ; then
    AM_CFLAGS="$AM_CFLAGS -Wall -W"
    AM_CXXFLAGS="$AM_CXXFLAGS -Wall -W"
fi

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])

AX_PTHREAD(,[AC_MSG_ERROR([unable to find pthreads, currently this is required])])

# Check for required includes
AC_CHECK_HEADERS([unistd.h direct.h])

AC_CHECK_FUNCS([strcasecmp])

# Check whether getcwd can dynamically allocate memory.
AC_MSG_CHECKING([whether getcwd(NULL, 0) works])
AC_CACHE_VAL([xml_cv_func_getcwd_null],
[AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <stdlib.h>
     #include <unistd.h>
     char *cwd = getcwd(NULL, 0);
     return (cwd != NULL) ? EXIT_SUCCESS : EXIT_FAILURE;]])],
  [xml_cv_func_getcwd_null=yes],
  [xml_cv_func_getcwd_null=no])])
AC_MSG_RESULT([$xml_cv_func_getcwd_null])
if test $xml_cv_func_getcwd_null = yes; then
AC_DEFINE([XSEC_HAVE_GETCWD_DYN], [1],
  [Define to 1 if getcwd(NULL, 0) works])
fi

AC_LANG(C++)

# Note that the pkg-config macros improperly set pkg_CFLAGS rather
# than CPPFLAGS and/or CXXFLAGS, so this requires some workarounds.
# Where possible, we clear the CFLAGS version to make sure nothing
# is depending on it downstream. Compile tests are favored over
# preproc-only tests so that CXXFLAGS should be sufficient.

AX_PKG_CHECK_MODULES([xerces],,[xerces-c >= 3.2])
xerces_CXXFLAGS=$xerces_CFLAGS
xerces_CFLAGS=""
AC_SUBST([xerces_CXXFLAGS])

AC_LANG(C)

# Crypto provider options (OpenSSL / NSS)

AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl],[use the OpenSSL crypto provider @<:@default=check@:>@])],,
    [with_openssl=check])

AS_IF([test x"$with_openssl" != xno],
    [AX_PKG_CHECK_MODULES([openssl],,[libcrypto],
        [with_openssl=found
         AC_DEFINE([XSEC_HAVE_OPENSSL],[1],[Define if OpenSSL is in use])

    # Now try to find out some things about this version of OpenSSL
   
    AX_SAVE_FLAGS_WITH_PREFIX([openssl],[[CFLAGS],[LIBS]]) 
    
    AC_MSG_CHECKING([for const input buffers in OpenSSL])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <openssl/rsa.h>]], [[ const unsigned char * buf;
    	  unsigned char * outbuf;
    	  RSA rsa;
    	  RSA_private_decrypt(1,buf,outbuf,&rsa,RSA_PKCS1_PADDING);]])],
    	[AC_MSG_RESULT([yes])
    	AC_DEFINE([XSEC_OPENSSL_CONST_BUFFERS],[1],[Define to 1 if OpenSSL uses const input buffers.])],
    	[AC_MSG_RESULT([no])])
    
    AC_CHECK_DECL(EVP_PKEY_id,
        [AC_DEFINE([XSEC_OPENSSL_HAVE_EVP_PKEY_ID],[1],[Define to 1 if OpenSSL has EVP_PKEY_id function.])],
        ,[#include <openssl/evp.h>])
    
    AC_MSG_CHECKING([for non-broken AES support])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/evp.h>]], [[ EVP_aes_256_cbc();
    	]])],[AC_MSG_RESULT([yes])
    	AC_DEFINE([XSEC_OPENSSL_HAVE_AES],[1],[Define to 1 if OpenSSL has full AES support.])],
    	[AC_MSG_RESULT([no])])

    AC_MSG_CHECKING([for GCM support])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <openssl/evp.h>]], [[ EVP_aes_256_gcm();
    	]])],[AC_MSG_RESULT([yes])
    	AC_DEFINE([XSEC_OPENSSL_HAVE_GCM],[1],[Define to 1 if OpenSSL has GCM support.])],
    	[AC_MSG_RESULT([no])])

    AC_CHECK_DECL(PKCS1_MGF1,
        [AC_DEFINE([XSEC_OPENSSL_HAVE_MGF1],[1],[Define to 1 if OpenSSL has PKCS1_MGF1 function.])],
        ,[#include <openssl/rsa.h>])
    
    AC_CHECK_DECL(EVP_PKEY_set1_EC_KEY,
        [AC_DEFINE([XSEC_OPENSSL_HAVE_EC],[1],[Define to 1 if OpenSSL has EC support.])],
        ,[#include <openssl/evp.h>])
    
    AC_CHECK_DECL(EVP_sha512,
        [AC_DEFINE([XSEC_OPENSSL_HAVE_SHA2],[1],[Define to 1 if OpenSSL has SHA2 support.])],
        ,[#include <openssl/evp.h>])
    
    AC_CHECK_DECL(EVP_CIPHER_CTX_set_padding,
    	[AC_DEFINE([XSEC_OPENSSL_CANSET_PADDING],[1],[Define to 1 if OpenSSL has EVP_CIPHER_CTX_set_padding.])],
    	,[#include <openssl/evp.h>])
    
    AC_CHECK_DECL(CRYPTO_cleanup_all_ex_data,
    	[AC_DEFINE([XSEC_OPENSSL_HAVE_CRYPTO_CLEANUP_ALL_EX_DATA],[1],[Define to 1 if OpenSSL has CRYPTO_cleanup_all_ex_data.])],
    	,[#include <openssl/crypto.h>])
    
    AC_MSG_CHECKING([for const input buffer in loadX509Base64Bin])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <openssl/x509.h>]], [[ const unsigned char * buf; d2i_X509(NULL, &buf, 1);]])],
        [AC_MSG_RESULT([yes])
    	AC_DEFINE([XSEC_OPENSSL_D2IX509_CONST_BUFFER],[1],[Define to 1 if OpenSSL X509 API has const input buffer.])],
    	[AC_MSG_RESULT([no])])

    AX_RESTORE_FLAGS_WITH_PREFIX([openssl],[[CFLAGS],[LIBS]])

        ],[AS_IF([test "x$with_openssl" != xcheck],[AC_MSG_ERROR([Unable to find OpenSSL])])])       
    ])

# Populate the Makefile conditionals
AM_CONDITIONAL([XSEC_AM_HAVE_OPENSSL],[test "x$with_openssl" = xfound])

# output the Makefiles
AC_OUTPUT
