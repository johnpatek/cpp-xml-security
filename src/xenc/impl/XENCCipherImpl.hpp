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
 * XENCCipherImpl := Implementation of the main encryption worker class
 *
 * $Id$
 *
 */

#ifndef XENCCIPHERIMPL_INCLUDE
#define XENCCIPHERIMPL_INCLUDE

// XSEC Includes

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/xenc/XENCCipher.hpp>

class safeBuffer;
class XSECProvider;
class XENCEncryptedDataImpl;
class TXFMChain;
class XSECEnv;
class XSECKeyInfoResolver;
class XSECPlatformUtils;

XSEC_DECLARE_XERCES_CLASS(DOMNode);
XSEC_DECLARE_XERCES_CLASS(DOMDocumentFragment);

class XENCCipherImpl : public  XENCCipher {

public:

	virtual ~XENCCipherImpl();

	// Implementation for decrypting elements

	XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument * 
		decryptElement(XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * element);

	// Implementation for encryption Elements
	XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument * encryptElement(
		XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * element,
		encryptionMethod em,
		const XMLCh * uri = NULL);

	// Getter methods
	XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument * getDocument(void) 
		{return mp_doc;}
	const XMLCh * getXENCNSPrefix(void) const;

	// Setter methods
	void setKey(XSECCryptoKey * key) {mp_key = key;}
	void setKeyInfoResolver(const XSECKeyInfoResolver * resolver);

	void setXENCNSPrefix(const XMLCh * prefix);
	
	// Creation methods
	XENCEncryptedData * createEncryptedData(XENCCipherData::XENCCipherDataType type,
											const XMLCh * algorithm,
											const XMLCh * value);

protected:

	// Initialisation
	static void Initialise(void);

protected:

	// Protected to prevent direct creation of objects
	XENCCipherImpl(XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument * doc);

private:

	// Internal functions
	XERCES_CPP_NAMESPACE_QUALIFIER DOMDocumentFragment 
							* deSerialise(
								safeBuffer &content, 
								XERCES_CPP_NAMESPACE_QUALIFIER DOMNode * ctx
							);

	// Unimplemented constructor
	XENCCipherImpl();

	XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument				
							* mp_doc;			// Document against which this will operate

	// Current working object
	XENCEncryptedDataImpl	* mp_encryptedData;

	// Key
	XSECCryptoKey			* mp_key;

	// Environment
	XSECEnv					* mp_env;

	// Resolvers
	XSECKeyInfoResolver		* mp_keyInfoResolver;

	friend class XSECProvider;
	friend class XSECPlatformUtils;

};

#endif /* XENCCIPHERIMPL_INCLUDE */

