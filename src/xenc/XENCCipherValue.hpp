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
 * XENCCipherValue := Interface definition for CipherValue element
 *
 * $Id$
 *
 */

#ifndef XENCCIPHERVALUE_INCLUDE
#define XENCCIPHERVALUE_INCLUDE

// XSEC Includes

#include <xsec/framework/XSECDefs.hpp>

/**
 * @ingroup xenc
 * @{
 */

/**
 * @brief Interface definition for the CipherValue object
 *
 * The \<CipherValue\> element holds the base64 encoded, encrypted data.
 * This is a very simple class that acts purely as a holder of data.
 *
 */


class XENCCipherValue {

	/** @name Constructors and Destructors */
	//@{

protected:

	XENCCipherValue() {};

public:

	virtual ~XENCCipherValue() {};

	/** @name Get Interface Methods */
	//@{

	/**
	 * \brief Get the encrypted information
	 *
	 * CipherValue nodes contain a text child that holds the base64 encoded
	 * cipher text that needs to be decrypted.  This call will return the
	 * base64 encoded string.
	 *
	 * @returns The Encrypted information in a base64 encoded string
	 */

	virtual const XMLCh * getCipherString(void) = 0;

	//@}

	/** @name Set Interface Methods */
	//@{

	/**
	 * \brief Set the encrypted value
	 *
	 * Sets the base64 encoded string held in the CipherValue.
	 *
	 * @note This should not normally be called directly - use the XENCCipher
	 * interface for normal operation
	 *
	 * @param value The string to set
	 */

	virtual void setCipherString(const XMLCh * value) = 0;

	//@}
private:

	// Unimplemented
	XENCCipherValue(const XENCCipherValue &);
	XENCCipherValue & operator = (const XENCCipherValue &);

};

#endif /* XENCCIPHERVALUE_INCLUDE */

