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
 * XSECCryptoUtils:= Helper crypo utilities that make life easier
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/framework/XSECError.hpp>
#include <xsec/enc/XSECCryptoUtils.hpp>
#include <xsec/enc/XSECCryptoKeyHMAC.hpp>
#include <xsec/utils/XSECPlatformUtils.hpp>

#include "../utils/XSECAlgorithmSupport.hpp"
#include "../utils/XSECAutoPtr.hpp"
#include "../utils/XSECDOMUtils.hpp"

#include <xercesc/util/Janitor.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

XERCES_CPP_NAMESPACE_USE


// --------------------------------------------------------------------------------
//           Some Base64 helpers
// --------------------------------------------------------------------------------

XMLCh XSEC_EXPORT * EncodeToBase64XMLCh(unsigned char * input, int inputLen) {

    XSECCryptoBase64 * b64 = XSECPlatformUtils::g_cryptoProvider->base64();
    Janitor<XSECCryptoBase64> j_b64(b64);
    unsigned char * output;
    int outputLen = ((4 * inputLen) / 3) + 5;
    XSECnew(output, unsigned char[outputLen]);
    ArrayJanitor<unsigned char> j_output(output);

    b64->encodeInit();
    int j = b64->encode(input, inputLen, output, outputLen - 1);
    j += b64->encodeFinish(&output[j], outputLen - j - 1);

    // Strip any trailing \n\r
    while (j > 0 && (output[j-1] == '\n' || output[j-1] == '\r'))
        j--;

    // Now transcode and get out of here
    output[j] = '\0';
    return XMLString::transcode((char *) output);

}

unsigned int XSEC_EXPORT DecodeFromBase64XMLCh(const XMLCh * input, unsigned char * output, int maxOutputLen) {

    XSECCryptoBase64 * b64 = XSECPlatformUtils::g_cryptoProvider->base64();
    Janitor<XSECCryptoBase64> j_b64(b64);

    XSECAutoPtrChar tinput(input);

    b64->decodeInit();
    unsigned int j = b64->decode((unsigned char *) tinput.get(), (unsigned int) strlen(tinput.get()), output, maxOutputLen - 1);
    j += b64->decodeFinish(&output[j], maxOutputLen - j - 1);

    return j;
}

unsigned int XSEC_EXPORT DecodeFromBase64(const char * input, unsigned char * output, int maxOutputLen) {

    XSECCryptoBase64 * b64 = XSECPlatformUtils::g_cryptoProvider->base64();
    Janitor<XSECCryptoBase64> j_b64(b64);

    b64->decodeInit();
    unsigned int j = b64->decode((unsigned char *) input, (unsigned int) strlen(input), output, maxOutputLen - 1);
    j += b64->decodeFinish(&output[j], maxOutputLen - j - 1);

    return j;
}


// --------------------------------------------------------------------------------
//           Some stuff to help with wierd signatures
// --------------------------------------------------------------------------------

const unsigned char ASNDSAProlog[] = {0x30, 0x2c, 0x02, 0x14};
const unsigned char ASNDSAMiddle[] = {0x02, 0x14};

bool ASN2DSASig(const unsigned char * input, unsigned char * r, unsigned char * s) {

    if (memcmp(ASNDSAProlog, input, 4) != 0 ||
        memcmp(ASNDSAMiddle, &input[24], 2) != 0)

        return false;

    memcpy(r, &input[4], 20);
    memcpy(s, &input[26], 20);

    return true;

}


// --------------------------------------------------------------------------------
//           Calculate correct OIDs for an RSA sig
// --------------------------------------------------------------------------------

/* As per RSA's PKCS #1 v 2.1, Section 9.2 Note 1, the DER encodings for
 * the has types are as follows:
 *
 * MD2: (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10 || H.
 * MD5: (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 || H.
 * SHA-1: (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
 * SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
 * SHA-384: (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
 * SHA-512: (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.
 *
 * More recently the following has been provided for SHA-224
 *
 * SHA-224: 30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c
 *
 */

int MD5OIDLen = 18;
unsigned char MD5OID[] = {
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
    0x04, 0x10
};


int sha1OIDLen = 15;
unsigned char sha1OID[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
    0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
};

int sha224OIDLen = 19;
unsigned char sha224OID[] = {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c
};

int sha256OIDLen = 19;
unsigned char sha256OID[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};

int sha384OIDLen = 19;
unsigned char sha384OID[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30
};

int sha512OIDLen = 19;
unsigned char sha512OID[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
};


unsigned char* getRSASigOID(XSECCryptoHash::HashType type, int& oidLen) {

    switch (type) {

    case (XSECCryptoHash::HASH_MD5):
        oidLen = MD5OIDLen;
        return MD5OID;
    case (XSECCryptoHash::HASH_SHA1):
        oidLen = sha1OIDLen;
        return sha1OID;
    case (XSECCryptoHash::HASH_SHA224):
        oidLen = sha224OIDLen;
        return sha224OID;
    case (XSECCryptoHash::HASH_SHA256):
        oidLen = sha256OIDLen;
        return sha256OID;
    case (XSECCryptoHash::HASH_SHA384):
        oidLen = sha384OIDLen;
        return sha384OID;
    case (XSECCryptoHash::HASH_SHA512):
        oidLen = sha512OIDLen;
        return sha512OID;
    default:
        oidLen = 0;
        return NULL;

    }
}

XSECCryptoHash* XSECCryptoProvider::hash(const XMLCh* uri) const {

    return hash(XSECAlgorithmSupport::getHashType(uri));
}

XSECCryptoHash* XSECCryptoProvider::HMAC(const XMLCh* uri) const {

    return HMAC(XSECAlgorithmSupport::getHashType(uri));
}
