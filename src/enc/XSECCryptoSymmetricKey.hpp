/*
 * The Apache Software License, Version 1.1
 *
 *
 * Copyright (c) 2002-2003 The Apache Software Foundation.  All rights 
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:  
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "<WebSig>" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written 
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation and was
 * originally based on software copyright (c) 2001, Institute for
 * Data Communications Systems, <http://www.nue.et-inf.uni-siegen.de/>.
 * The development of this software was partly funded by the European 
 * Commission in the <WebSig> project in the ISIS Programme. 
 * For more information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

/*
 * XSEC
 *
 * XSECCryptoSymmetricKey := Bulk encryption algorithms should all be
 *							implemented via this interface
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */



#ifndef XSECCRYPTOSYMMETRICKEY_INCLUDE
#define XSECCRYPTOSYMMETRICKEY_INCLUDE

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/dsig/DSIGConstants.hpp>
#include <xsec/enc/XSECCryptoKey.hpp>

/**
 * \ingroup crypto
 * @{
 */

/**
 * \brief Base interface definition for symmetric key material.
 *
 * All symmetric algorithms are implemented via this interface.
 * Unlike the asymmetric key definitions, this is not further
 * extended for particular algorithms.  Rather it defines
 * encrypt/decrypt functions that are implemented within particular
 * providers for a particular algorithm.
 */

class DSIG_EXPORT XSECCryptoSymmetricKey : public XSECCryptoKey {

public :

	/**
	 * \brief Symmetric Key types understood by the library
	 *
	 * This type defines the list of symmetric key types that the library
	 * understands.
	 */

	enum SymmetricKeyType {

		KEY_NONE,
		KEY_3DES_192,			/** 192 bit (3-Key) 3DES */
		KEY_AES_128,			/** 128 bit AES */
		KEY_AES_192,			/** 192 bit AES */
		KEY_AES_256				/** 256 bit AES */

	};

	enum SymmetricKeyMode {

		MODE_NONE,					/** An error condition */
		MODE_ECB,					/** Electronic Code Book */
		MODE_CBC					/** Cipher Block Chaining */

	};


	/** @name Constructors and Destructors */
	//@{
	
	/**
	 * \brief Constructor
	 **/

	XSECCryptoSymmetricKey() {};

	/**
	 * \brief Destructor 
	 *
	 * Implementations must ensure that the held key is properly destroyed
	 * (overwritten) when key objects are deleted.
	 */

	virtual ~XSECCryptoSymmetricKey() {};

	//@}

	/** @name Basic CryptoKey Interface methods */
	//@{

	/**
	 * \brief Returns the type of this key.
	 */

	virtual KeyType getKeyType() {return KEY_SYMMETRIC;}

	/**
	 * \brief Returns a string that identifies the crypto owner of this library.
	 */

	virtual const XMLCh * getProviderName() = 0;

	/**
	 * \brief Clone the key
	 *
	 * All keys need to be able to copy themselves and return
	 * a pointer to the copy.  This allows the library to 
	 * duplicate keys.
	 */

	virtual XSECCryptoKey * clone() = 0;

	//@}

	/** @name Symmetric key interface methods */
	//@{

	/**
	 * \brief What type of symmetric key is this?
	 *
	 * There are a number of different types of symmetric key.
	 * This method allows callers to determine the type of this
	 * particular key
	 */

	virtual SymmetricKeyType getSymmetricKeyType(void) = 0;

	/**
	 * \brief Set the key from the provided bytes
	 *
	 * Symmetric keys can all be loaded from a buffer containing a series
	 * of bytes.
	 *
	 * @param key The buffer containing the key bytes
	 * @param keyLen The number of key bytes in the buffer
	 *
	 */

	virtual void setKey(const unsigned char * key, unsigned int keyLen) = 0;

	/**
	 * \brief Initialise an decryption process
	 *
	 * Setup the key to get ready for a decryption session.
	 * Callers can pass in an IV.  If one is not provided, 
	 * but the algorithm requires one (e.g. 3DES_CBC), then 
	 * implementations should assume that the start of the
	 * cipher text stream will in fact be the IV.
	 *
	 * @param doPad By default, we perform padding for last block
	 * @param mode mode selection (Currently ECB or CBC mode only).
	 * Default is CBC
	 * @param iv Initialisation Vector to be used.  NULL if one is
	 * not required, or if IV will be set from data stream
	 * @returns true if the initialisation succeeded.
	 */

	virtual bool decryptInit(bool doPad = true,
							 SymmetricKeyMode mode = MODE_CBC,
							 const unsigned char * iv = NULL) = 0;

	/**
	 * \brief Continue an decrypt operation using this key.
	 *
	 * Decryption must have been set up using an encryptInit
	 * call.  Takes the inBuf and continues a decryption operation,
	 * writing the output to outBuf.
	 *
	 * This function does not have to guarantee that all input
	 * will be decrypted.  In cases where the input is not a length
	 * of the block size, the implementation will need to hold back
	 * cipher-text to be handles during the next operation.
	 *
	 * @param inBuf Octets to be decrypted
	 * @param plainBuf Buffer to place output in
	 * @param inLength Number of bytes to decrypt
	 * @param maxOutLength Maximum number of bytes to place in output 
	 * buffer
	 * @returns Bytes placed in output Buffer
	 */

	virtual unsigned int decrypt(const unsigned char * inBuf, 
								 unsigned char * plainBuf, 
								 unsigned int inLength,
								 unsigned int maxOutLength) = 0;

	/**
	 * \brief Finish a decryption operation
	 *
	 * Complete a decryption process.  No cipher text is passed in,
	 * as this should simply be removing any remaining text from
	 * the plain storage buffer.
	 *
	 * May throw an exception if there is some stored cipher text
	 * that is not the length of the block size for block algorithms.
	 *
	 * @param plainBuf Buffer to place any remaining plain text in
	 * @param maxOutLength Maximum number of bytes to pace in output
	 * @returns Bytes placed in output buffer
	 */

	virtual unsigned int decryptFinish(unsigned char * plainBuf,
									   unsigned int maxOutLength) = 0;

	/**
	 * \brief Initialise an encryption process
	 *
	 * Setup the key to get ready for a decryption session.
	 * Callers can pass in an IV.  If one is not provided, 
	 * but the algorithm requires one (e.g. 3DES_CBC), then
	 * implementations are required to generate one.
	 *
	 * @param doPad By default, we perform padding for last block
	 * @param mode What mode to handle blocks (Currently CBC or ECB)
	 * Default is CBC.
	 * @param iv Initialisation Vector to be used.  NULL if one is
	 * not required, or if IV is to be generated
	 * @returns true if the initialisation succeeded.
	 */

	virtual bool encryptInit(bool doPad = true, 
							 SymmetricKeyMode mode = MODE_CBC,
							 const unsigned char * iv = NULL) = 0;

	/**
	 * \brief Continue an encryption operation using this key.
	 *
	 * Encryption must have been set up using an encryptInit
	 * call.  Takes the inBuf and continues a encryption operation,
	 * writing the output to outBuf.
	 *
	 * This function does not have to guarantee that all input
	 * will be encrypted.  In cases where the input is not a length
	 * of the block size, the implementation will need to hold back
	 * plain-text to be handled during the next operation.
	 *
	 * @param inBuf Octets to be encrypted
	 * @param cipherBuf Buffer to place output in
	 * @param inLength Number of bytes to encrypt
	 * @param maxOutLength Maximum number of bytes to place in output 
	 * buffer
	 * @returns Bytes placed in output Buffer
	 */

	virtual unsigned int encrypt(const unsigned char * inBuf, 
								 unsigned char * cipherBuf, 
								 unsigned int inLength,
								 unsigned int maxOutLength) = 0;

	/**
	 * \brief Finish a encryption operation
	 *
	 * Complete a encryption process.  No plain text is passed in,
	 * as this should simply be removing any remaining text from
	 * the plain storage buffer and creating a final padded block.
	 *
	 * Padding is performed by taking the remaining block, and
	 * setting the last byte to equal the number of bytes of
	 * padding.  If the plain was an exact multiple of the block size,
	 * then an extra block of padding will be used.  For example, if 
	 * the block size is 8 bytes, and there were three remaining plain
	 * text bytes (0x01, 0x02 and 0x03), the final block will be :
	 *
	 * 0x010203????????05
	 *
	 * @param cipherBuf Buffer to place final block of cipher text in
	 * @param maxOutLength Maximum number of bytes to pace in output
	 * @returns Bytes placed in output buffer
	 */

	virtual unsigned int encryptFinish(unsigned char * plainBuf,
									   unsigned int maxOutLength) = 0;

	//@}

};


#endif /* XSECCRYPTOSYMMETRICKEY_INCLUDE */
