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
 * OpenSSLCryptoKeyDSA := DSA Keys
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#ifndef OPENSSLCRYPTOKEYDSA_INCLUDE
#define OPENSSLCRYPTOKEYDSA_INCLUDE

#include <xsec/enc/XSECCryptoKeyDSA.hpp>

#if defined (XSEC_HAVE_OPENSSL)
#include <openssl/evp.h>

/**
 * \ingroup opensslcrypto
 */

/**
 * \brief OpenSSL implementation class for DSA keys.
 *
 * The library uses classes derived from this to process DSA keys.
 */


class XSEC_EXPORT OpenSSLCryptoKeyDSA : public XSECCryptoKeyDSA {

public :

    /** @name Constructors and Destructors */
    //@{
    
    OpenSSLCryptoKeyDSA();

    /**
     * \brief Destructor
     *
     * Will call the OpenSSL function to destroy the DSA key - which will
     * also overwrite any Private keys
     */

    virtual ~OpenSSLCryptoKeyDSA();

    //@}

    /** @name Required Key Interface methods */
    //@{

    /**
     * \brief Return the type of this key.
     *
     * Allows the caller (and library) to determine whether this is a 
     * public key, private key or a key pair
     */

    virtual XSECCryptoKey::KeyType getKeyType() const;

    /**
     *\brief Return the OpenSSL string identifier
     */

    virtual const XMLCh * getProviderName() const;

    /**
     * \brief Replicate key
     */

    virtual XSECCryptoKey * clone() const;

    //@}

    /** @name Required DSA methods */
    //@{

    /**
     * \brief Create a signature
     *
     * Sign the buffer using the internal private key.  Will throw a DSAError
     * if the key is not set, or is not a private key.
     *
     * @param hashBuf Buffer containing the pre-calculated (binary) digest
     * @param hashLen Number of bytes of hash in the hashBuf
     * @param base64SignatureBuf Buffer to place the base64 encoded result
     * in.
     * @param base64SignatureBufLen Implementations need to ensure they do
     * not write more bytes than this into the buffer
     */

    virtual unsigned int signBase64Signature(unsigned char * hashBuf,
        unsigned int hashLen,
        char * base64SignatureBuf,
        unsigned int base64SignatureBufLen) const;

    /**
     * \brief Verify a signature
     *
     * The library will call this function to validate a signature
     *
     * @param hashBuf Buffer containing the pre-calculated (binary) digest
     * @param hashLen Length of the data in the digest buffer
     * @param base64Signature Buffer containing the Base64 encoded signature
     * @param sigLen Length of the data in the signature buffer
     * @returns true if the signature was valid, false otherwise
     */


    virtual bool verifyBase64Signature(unsigned char * hashBuf, 
                             unsigned int hashLen,
                             char * base64Signature,
                             unsigned int sigLen) const;
    
    //@}

    /** @name Optional Interface methods
     * 
     * Have been fully implemented in the OpenSSL interface to allow interop
     * testing to occur.
     *
     */
    //@{

    /**
     * \brief Load P
     *
     * @param b64 Base64 encoded parameter - read from XML document
     * @param len Length of the encoded string
     */

    virtual void loadPBase64BigNums(const char * b64, unsigned int len);

    /**
     * \brief Load Q
     *
     * @param b64 Base64 encoded parameter - read from XML document
     * @param len Length of the encoded string
     */

    virtual void loadQBase64BigNums(const char * b64, unsigned int len);
    
    /**
     * \brief Load G
     *
     * @param b64 Base64 encoded parameter - read from XML document
     * @param len Length of the encoded string
     */

    virtual void loadGBase64BigNums(const char * b64, unsigned int len);

    /**
     * \brief Load Y
     *
     * @param b64 Base64 encoded parameter - read from XML document
     * @param len Length of the encoded string
     */

    virtual void loadYBase64BigNums(const char * b64, unsigned int len);

    /**
     * \brief Load J
     *
     * @param b64 Base64 encoded parameter - read from XML document
     * @param len Length of the encoded string
     */

    virtual void loadJBase64BigNums(const char * b64, unsigned int len);

    //@}

    /** @name OpenSSL Specific functions */
    //@{

    /**
     * \brief Library specific constructor
     *
     * Used to create a new key around an OpenSSL EVP_PKEY object
     * holding a DSA key
     */

    OpenSSLCryptoKeyDSA(EVP_PKEY *k);

    /**
     * \brief Get OpenSSL DSA structure
     */

    DSA * getOpenSSLDSA(void) {return mp_dsaKey;}

    /**
     * \brief Get OpenSSL DSA structure
     */

    const DSA * getOpenSSLDSA(void) const {return mp_dsaKey;}

    //@}
    //@}


private:
    DSA                             * mp_dsaKey;

    /**
     * \brief storage for accumulating p/q/r
     *
     * In OpenSSL 1.1 the DSA structure is opaque and there is only
     * a setter for p + q + g and they all must be non NULL.
     *
     * We have setters for each one individually, so we have to store them and
     * then when they are all set we can call OpenSSL's setter.
     */
    BIGNUM *mp_accumP, *mp_accumQ, *mp_accumG;

    void setPBase(BIGNUM *pBase);
    void setQBase(BIGNUM *pBase);
    void setGBase(BIGNUM *pBase);
    void commitPQG();
};

#endif /* XSEC_HAVE_OPENSSL */
#endif /* XSECCRYPTOKEYDSA_INCLUDE */
