/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * XSEC
 *
 * Configuration file for Windows platform
 *
 * Needs to be modified by hand
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */


/*
 * Define presence of cryptographic providers.
 */

// #define XSEC_HAVE_OPENSSL 1

/*
 * Some settings for OpenSSL if we have it
 *
 */

#if defined (XSEC_HAVE_OPENSSL)

#	include <openssl/opensslv.h>
#	if (OPENSSL_VERSION_NUMBER >= 0x10001000)
#		define XSEC_OPENSSL_CONST_BUFFERS
#		define XSEC_OPENSSL_HAVE_AES
#       define XSEC_OPENSSL_HAVE_EC
#		define XSEC_OPENSSL_CANSET_PADDING
#		define XSEC_OPENSSL_HAVE_CRYPTO_CLEANUP_ALL_EX_DATA
#		define XSEC_OPENSSL_D2IX509_CONST_BUFFER
#       define XSEC_OPENSSL_HAVE_SHA2
#       define XSEC_OPENSSL_HAVE_MGF1
#       define XSEC_OPENSSL_HAVE_EVP_PKEY_ID
#		define XSEC_OPENSSL_HAVE_GCM
#   else
#       error "OpenSSL version 1.0.1 or later is required"
#	endif

#endif

/*
 * Macros used to determine what header files exist on this
 * system
 */

/* Posix unistd.h */
/* #define HAVE_UNISTD_H */

/* Windows direct.h */
#define HAVE_DIRECT_H 1

/* Define to 1 if getcwd(NULL, 0) works. */
#define XSEC_HAVE_GETCWD_DYN 1

#include <xsec/framework/XSECVersion.hpp>
