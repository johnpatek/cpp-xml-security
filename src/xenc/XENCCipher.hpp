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
 * XENCCipher := Interface definition for main encryption worker class
 *
 * $Id$
 *
 */

#ifndef XENCCIPHER_INCLUDE
#define XENCCIPHER_INCLUDE

// XSEC Includes

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/xenc/XENCCipherData.hpp>

// Xerces

XSEC_DECLARE_XERCES_CLASS(DOMElement);
XSEC_DECLARE_XERCES_CLASS(DOMDocument);

class XSECCryptoKey;
class XENCEncryptedData;

/**
 * @defgroup xenc XML Encryption Implementation
 *
 * <p>The classes in this group implement the XML Encryption
 * standard.  In most cases, users should interact with these
 * functions via the XENCCipher class</p>
 *
 *\@{*/



/**
 * @brief Main worker class for the XSEC implementation of XML
 * Encryption.
 *
 * The XENCCipher class not something that is directly defined in
 * the XML Encryption standard.  It is a control class used by the
 * library to generate encrypted XML information and to decrypt
 * information held in XML Encryption structures.
 *
 * All encryption and decryption work performed by the library is
 * handled within this class.  The other XENC classes simply
 * handle marshalling and unmarshalling of the DOM data.
 *
 */


class XENCCipher {

public:
	
	/** @name Constructors and Destructors */
	//@{
	
	virtual ~XENCCipher() {};

	//@}

	/** @name Decryption Functions */
	//@{

	/**
	 * \brief Decrypt the nominated element.
	 *
	 * Decrypts the passed in element, which must be the root
	 * node of a \<EncryptedData\> method with a type of "#Element".
	 * If not, the library will throw an XSECException exception.
	 *
	 * This is an "all in one method".  The library will replace
	 * the passed in Element (i.e. the encrypted XML data) with
	 * the resultant plain text, after it has been parsed back into
	 * DOM nodes
	 *
	 * @param element Root of EncryptedData DOM structyre to decrypt
	 * @returns The owning document with the element replaced, or NULL
	 * if the decryption fails for some reason (normally an exception).
	 * @throws XSECException if the decryption fails, or if this is
	 * not a valid EncryptedData DOM structure.
	 */

	virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument * decryptElement(
		XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * element
	) = 0;

	//@}

	/** @name Encryption Functions */
	//@{

	/**
	 * \brief Encrypt the nominated element.
	 * 
	 * Encrypts the passed in element and all children.  The element
	 * is replaced with an EncryptedData element
	 *
	 * @param element Element (and children) to encrypt
	 * @returns The owning document with the element replaced, or NULL
	 * if the decryption fails for some reason (normally an exception).
	 * @throws XSECException if the encryption fails.
	 */

	virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument * encryptElement(
		XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * element
	) = 0;

	//@}
	/** @name Getter Functions */
	//@{

	/**
	 * \brief Get owning document
	 *
	 * Every Cipher object is associated with an owning document (for generation of
	 * nodes etc.)  This allows callers to retrieve this value.
	 *
	 * @returns The DOMDocument that is used by this object
	 */

	virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument * getDocument(void) = 0;

	/**
	 * \brief Get namespace prefix for XENC nodes
	 *
	 * Find the string being used by the library to prefix nodes in the 
	 * xenc: namespace.
	 *
	 * @returns XENC namespace prefix
	 */

	virtual const XMLCh * getXENCNSPrefix(void) const = 0;

	//@}

	/** @name Setter Functions */
	//@{

	/**
	 * \brief Set decryption key for next operation
	 *
	 * Set the passed in key for the next decryption/encryption
	 * operation.
	 *
	 * @param key Key to use
	 * @note This function will take ownership of the key and delete it when done.
	 */

	virtual void setKey(XSECCryptoKey * key) = 0;

	/**
	 * \brief Set prefix for XENC nodes
	 *
	 * Set the namespace prefix the library will use when creating
	 * nodes in the XENC namespace
	 */

	virtual void setXENCNSPrefix(const XMLCh * prefix) = 0;

	//@}

	/** @name Creation Functions */
	//@{

	/**
	 * \brief Create a new EncryptedData element
	 *
	 * Method for creating a basic Encrypted Data element.  Can be used
	 * in cases where an application needs to build this from scratch.
	 *
	 * In general, applications should use the higher level methods such
	 * as #encryptElement or #encryptElementContent.
	 *
	 * @note The Cipher object will take on this new object as the current
	 * EncryptedData and delete any currently being held.
	 *
	 * @param type Should this set up a CipherReference or a CipherValue
	 * @param value String to set the cipher data to if the type is VALUE_TYPE
	 * @returns An XENCEncryptedData object
	 */

	virtual XENCEncryptedData * createEncryptedData(XENCCipherData::XENCCipherDataType type, 
													XMLCh * value) = 0;

	//@}

};

/*\@}*/

#endif /* XENCCIPHER_INCLUDE */

