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
 * XSECCryptoKeyRSA := RSA Keys
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#ifndef OPENSSLCRYPTOKEYRSA_INCLUDE
#define OPENSSLCRYPTOKEYRSA_INCLUDE

#include <xsec/enc/XSECCryptoKeyRSA.hpp>

#if defined (XSEC_HAVE_OPENSSL)
#include <openssl/evp.h>

/**
 * \ingroup opensslcrypto
 */

/**
 * \brief Implementation of the interface class for RSA keys.
 *
 * The library uses classes derived from this to process RSA keys.
 */

class XSEC_EXPORT OpenSSLCryptoKeyRSA : public XSECCryptoKeyRSA {

public :

    /** @name Constructors and Destructors */
    //@{

    OpenSSLCryptoKeyRSA();
    virtual ~OpenSSLCryptoKeyRSA();

    //@}

    /** @name Key Interface methods */
    //@{

    /**
     * \brief Return the type of this key.
     *
     * For RSA keys, this allows people to determine whether this is a
     * public key, private key or a key pair
     */

    virtual XSECCryptoKey::KeyType getKeyType() const;

    /**
     * \brief Return the OpenSSL identifier string
     */

    virtual const XMLCh* getProviderName() const;

    /**
     * \brief Replicate key
     */

    virtual XSECCryptoKey* clone() const;

    //@}

    /** @name Mandatory RSA interface methods
     *
     * These methods are required by the library.
     */
    //@{


    /**
     * \brief Verify a SHA1 PKCS1 encoded signature
     *
     * The library will call this function to validate an RSA signature
     * The standard by default uses SHA1 in a PKCS1 encoding.
     *
     * @param hashBuf Buffer containing the pre-calculated (binary) digest
     * @param hashLen Length of the data in the digest buffer
     * @param base64Signature Buffer containing the Base64 encoded signature
     * @param sigLen Length of the data in the signature buffer
     * @param type The hash method that was used to create the hash that is being
     * passed in
     * @returns true if the signature was valid, false otherwise
     */

    virtual bool verifySHA1PKCS1Base64Signature(const unsigned char* hashBuf,
                                 unsigned int hashLen,
                                 const char* base64Signature,
                                 unsigned int sigLen,
                                 XSECCryptoHash::HashType type) const;

    /**
     * \brief Create a signature
     *
     * The library will call this function to create a signature from
     * a pre-calculated digest.  The output signature will
     * be Base64 encoded such that it can be placed directly into the
     * XML document
     *
     * @param hashBuf Buffer containing the pre-calculated (binary) digest
     * @param hashLen Number of bytes of hash in the hashBuf
     * @param base64SignatureBuf Buffer to place the base64 encoded result
     * in.
     * @param base64SignatureBufLen Implementations need to ensure they do
     * not write more bytes than this into the buffer
     * @param type Hash Method used in order to embed correct OID for sig
     */

    virtual unsigned int signSHA1PKCS1Base64Signature(unsigned char* hashBuf,
        unsigned int hashLen,
        char* base64SignatureBuf,
        unsigned int base64SignatureBufLen,
        XSECCryptoHash::HashType type) const;

    /**
     * \brief Decrypt using private key
     *
     * The library will call this function to decrypt a piece of cipher
     * text using the private component of this key.
     *
     * @param inBuf cipher text to decrypt
     * @param plainBuf output buffer for decrypted bytes
     * @param inLength bytes of cipher text to decrypt
     * @param maxOutLength size of outputBuffer
     * @param padding Type of padding (PKCS 1.5 or OAEP)
     * @param hashURI Hash Method for OAEP encryption
     * @param mgfURI algorithm identifier for OAEP mask generation function
     * @param params raw OAEP parameter data, if any
     * @param paramslen OEP parameter length
     */

    virtual unsigned int privateDecrypt(const unsigned char* inBuf,
                                 unsigned char* plainBuf,
                                 unsigned int inLength,
                                 unsigned int maxOutLength,
                                 PaddingType padding,
                                 const XMLCh* hashURI=NULL,
                                 const XMLCh* mgfURI=NULL,
                                 unsigned char* params=NULL,
                                 unsigned int paramsLen=0) const;


    /**
     * \brief Encrypt using a public key
     *
     * The library will call this function to encrypt a plain text buffer
     * using the public component of this key.
     *
     * @param inBuf plain text to decrypt
     * @param cipherBuf output buffer for decrypted bytes
     * @param inLength bytes of plain text to encrypt
     * @param maxOutLength size of outputBuffer
     * @param padding Type of padding (PKCS 1.5 or OAEP)
     * @param hashURI Hash Method for OAEP encryption
     * @param mgfURI algorithm identifier for OAEP mask generation function
     * @param params raw OAEP parameter data, if any
     * @param paramslen OEP parameter length
     */

    virtual unsigned int publicEncrypt(const unsigned char* inBuf,
                                 unsigned char* cipherBuf,
                                 unsigned int inLength,
                                 unsigned int maxOutLength,
                                 PaddingType padding,
                                 const XMLCh* hashURI=NULL,
                                 const XMLCh* mgfURI=NULL,
                                 unsigned char* params=NULL,
                                 unsigned int paramsLen=0) const;

    /**
     * \brief Obtain the length of an RSA key
     *
     * @returns The length of the rsa key (in bytes)
     */

    virtual unsigned int getLength() const;

    //@}

    /** @name Optional Interface methods
     *
     * Have been implemented to allow interoperability testing
     */

    //@{

    /**
     * \brief Load the modulus
     *
     * Load the modulus from a Base64 encoded string
     *
     * param b64 A buffer containing the encoded string
     * param len The length of the data in the buffer
     */

    virtual void loadPublicModulusBase64BigNums(const char* b64, unsigned int len);

    /**
     * \brief Load the exponent
     *
     * Load the exponent from a Base64 encoded string
     *
     * param b64 A buffer containing the encoded string
     * param len The length of the data in the buffer
     */

    virtual void loadPublicExponentBase64BigNums(const char* b64, unsigned int len);

    //@}

    /** @name OpenSSL specific methods */
    //@{

    /**
     * \brief Constructor to create the object around an existing OpenSSL RSA
     * key
     *
     * @param k The key to copy
     * @note The object takes a copy of the original key, and will not delete k on
     * completion.  This must be done by the caller.
     */

    OpenSSLCryptoKeyRSA(EVP_PKEY* k);

    /**
     * \brief Get OpenSSL RSA Object
     */

    RSA* getOpenSSLRSA() {return mp_rsaKey;}

    /**
     * \brief Get OpenSSL RSA Object
     */

    const RSA* getOpenSSLRSA() const {return mp_rsaKey;}

    //@}

private:

    RSA* mp_rsaKey;

    BIGNUM *mp_accumE, *mp_accumN;
    void setEBase(BIGNUM *eBase);
    void setNBase(BIGNUM *nBase);
    void commitEN();

};

#endif /* XSEC_HAVE_OPENSSL */
#endif /* OPENSSLCRYPTOKEYRSA_INCLUDE */
