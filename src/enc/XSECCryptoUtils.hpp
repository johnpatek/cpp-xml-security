/*
 * Copyright 2002-2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * imitations under the License.
 */

/*
 * XSEC
 *
 * XSECCryptoUtils:= Helper crypo utilities that make life easier
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#ifndef XSECCRYPTOUTILS_INCLUDE
#define XSECCRYPTOUTILS_INCLUDE

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/utils/XSECSafeBuffer.hpp>

/**
 * \brief Helper utilities for crypto.
 * @ingroup crypto
 */

// --------------------------------------------------------------------------------
//           XKMS Limited-Use Shared Secret handling
// --------------------------------------------------------------------------------

#define XKMSAuthenticationValue					0x01
#define	XKMSRevocationCodeIdenfitierEncoding1	0x02
#define	XKMSRevocationCodeIdenfitierEncoding2	0x03
#define XKMSKeyEncryption						0x04

int DSIG_EXPORT CalculateXKMSAuthenticationKey(unsigned char * input, int inputLen, unsigned char * output, int maxOutputLen);
int DSIG_EXPORT CalculateXKMSRevocationCodeIdentifierEncoding1(unsigned char * input, int inputLen, unsigned char * output, int maxOutputLen);
/* Calculate encoding 2 - Input is original pass phrase */
int DSIG_EXPORT CalculateXKMSRevocationCodeIdentifierEncoding2(unsigned char * input, int inputLen, unsigned char * output, int maxOutputLen);
/* Calculate encoding 2 - Input is encoding 1 */
int DSIG_EXPORT CalculateXKMSRevocationCodeIdentifierEncoding2From1(unsigned char * input, int inputLen, unsigned char * output, int maxOutputLen);
int DSIG_EXPORT CalculateXKMSKEK(unsigned char * input, int inputLen, unsigned char * output, int maxOutputLen);

// --------------------------------------------------------------------------------
//           Some Base64 helpers
// --------------------------------------------------------------------------------

XMLCh DSIG_EXPORT * EncodeToBase64XMLCh(unsigned char * input, int inputLen);

#endif /* XSECCRYPTOUTILS_INCLUDE */


