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
 * xtest := basic test application to run through a series of tests of
 *			the XSEC library.
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#include <xsec/framework/XSECDefs.hpp> 

#include <cassert>

#include <memory.h>
#include <iostream>
#include <stdlib.h>

#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/framework/XMLFormatter.hpp>
#include <xercesc/framework/StdOutFormatTarget.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>

#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLException.hpp>

#include <xsec/transformers/TXFMOutputFile.hpp>
#include <xsec/dsig/DSIGTransformXPath.hpp>
#include <xsec/dsig/DSIGTransformXPathFilter.hpp>
#include <xsec/dsig/DSIGTransformC14n.hpp>

// XALAN

#ifndef XSEC_NO_XALAN

#include <xalanc/XPath/XPathEvaluator.hpp>
#include <xalanc/XalanTransformer/XalanTransformer.hpp>

XALAN_USING_XALAN(XPathEvaluator)
XALAN_USING_XALAN(XalanTransformer)

#endif

// XSEC

#include <xsec/utils/XSECPlatformUtils.hpp>
#include <xsec/framework/XSECProvider.hpp>
#include <xsec/canon/XSECC14n20010315.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/framework/XSECError.hpp>
#include <xsec/dsig/DSIGSignature.hpp>
#include <xsec/utils/XSECNameSpaceExpander.hpp>
#include <xsec/utils/XSECDOMUtils.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/dsig/DSIGKeyInfoX509.hpp>
#include <xsec/dsig/DSIGKeyInfoName.hpp>
#include <xsec/dsig/DSIGKeyInfoPGPData.hpp>
#include <xsec/dsig/DSIGKeyInfoSPKIData.hpp>
#include <xsec/dsig/DSIGKeyInfoMgmtData.hpp>
#include <xsec/xenc/XENCCipher.hpp>
#include <xsec/xenc/XENCEncryptedData.hpp>

#if defined (HAVE_OPENSSL)
#	include <xsec/enc/OpenSSL/OpenSSLCryptoKeyHMAC.hpp>
#	include <xsec/enc/OpenSSL/OpenSSLCryptoSymmetricKey.hpp>
#	include <openssl/rand.h>
#endif
#if defined (HAVE_WINCAPI)
#	include <xsec/enc/WinCAPI/WinCAPICryptoKeyHMAC.hpp>
#endif

using std::ostream;
using std::cout;
using std::cerr;
using std::endl;
using std::flush;

/*
 * Because of all the characters, it's easiest to inject entire Xerces namespace
 * into global
 */

XERCES_CPP_NAMESPACE_USE

// --------------------------------------------------------------------------------
//           Global variables
// --------------------------------------------------------------------------------

bool	g_printDocs = false;
// --------------------------------------------------------------------------------
//           Known "Good" Values
// --------------------------------------------------------------------------------

unsigned char createdDocRefs [9][20] = {
	{ 0x51, 0x3c, 0xb5, 0xdf, 0xb9, 0x1e, 0x9d, 0xaf, 0xd4, 0x4a,
	  0x95, 0x79, 0xf1, 0xd6, 0x54, 0xe, 0xb0, 0xb0, 0x29, 0xe3, },
	{ 0x51, 0x3c, 0xb5, 0xdf, 0xb9, 0x1e, 0x9d, 0xaf, 0xd4, 0x4a, 
	  0x95, 0x79, 0xf1, 0xd6, 0x54, 0xe, 0xb0, 0xb0, 0x29, 0xe3, },
	{ 0x52, 0x74, 0xc3, 0xe4, 0xc5, 0xf7, 0x20, 0xb0, 0xd9, 0x52, 
	  0xdb, 0xb3, 0xee, 0x46, 0x66, 0x8f, 0xe1, 0xb6, 0x30, 0x9d, },
	{ 0x5a, 0x14, 0x9c, 0x5a, 0x40, 0x34, 0x51, 0x4f, 0xef, 0x1d, 
	  0x85, 0x44, 0xc7, 0x2a, 0xd3, 0xd2, 0x2, 0xed, 0x67, 0xb4, },
	{ 0x88, 0xd1, 0x65, 0xed, 0x2a, 0xe7, 0xc0, 0xbd, 0xea, 0x3e, 
	  0xe6, 0xf3, 0xd4, 0x8c, 0xf7, 0xdd, 0xc8, 0x85, 0xa9, 0x6d, },
	{ 0x52, 0x74, 0xc3, 0xe4, 0xc5, 0xf7, 0x20, 0xb0, 0xd9, 0x52, 
	  0xdb, 0xb3, 0xee, 0x46, 0x66, 0x8f, 0xe1, 0xb6, 0x30, 0x9d, },
	{ 0x52, 0x74, 0xc3, 0xe4, 0xc5, 0xf7, 0x20, 0xb0, 0xd9, 0x52, 
	  0xdb, 0xb3, 0xee, 0x46, 0x66, 0x8f, 0xe1, 0xb6, 0x30, 0x9d, },
	{ 0x3c, 0x80, 0x4, 0x94, 0xa5, 0xbe, 0xf6, 0x16, 0x40, 0xe0, 
  	  0x24, 0xd5, 0x65, 0x39, 0xc, 0x18, 0x21, 0x3d, 0xa5, 0x51, },
  	{ 0x51, 0x3c, 0xb5, 0xdf, 0xb9, 0x1e, 0x9d, 0xaf, 0xd4, 0x4a, 
	  0x95, 0x79, 0xf1, 0xd6, 0x54, 0xe, 0xb0, 0xb0, 0x29, 0xe3, }

};

// --------------------------------------------------------------------------------
//           Some test data
// --------------------------------------------------------------------------------

// "CN=<Test,>,O=XSEC  "

XMLCh s_tstDName[] = {

	chLatin_C,
	chLatin_N,
	chEqual,
	chOpenAngle,
	chLatin_T,
	chLatin_e,
	chLatin_s,
	chLatin_t,
	chComma,
	chCloseAngle,
	chComma,
	chLatin_O,
	chEqual,
	chLatin_X,
	chLatin_S,
	chLatin_E,
	chLatin_C,
	chSpace,
	chSpace,
	chNull

};

XMLCh s_tstKeyName[] = {

	chLatin_F, chLatin_r, chLatin_e, chLatin_d, chSingleQuote,
	chLatin_s, chSpace, chLatin_n, chLatin_a, chLatin_m,
	chLatin_e, chNull
};

XMLCh s_tstPGPKeyID[] = {

	chLatin_D, chLatin_u, chLatin_m, chLatin_m, chLatin_y, chSpace,
	chLatin_P, chLatin_G, chLatin_P, chSpace,
	chLatin_I, chLatin_D, chNull
};

XMLCh s_tstPGPKeyPacket[] = {

	chLatin_D, chLatin_u, chLatin_m, chLatin_m, chLatin_y, chSpace,
	chLatin_P, chLatin_G, chLatin_P, chSpace,
	chLatin_P, chLatin_a, chLatin_c, chLatin_k, chLatin_e, chLatin_t, chNull
};

XMLCh s_tstSexp1[] = {

	chLatin_D, chLatin_u, chLatin_m, chLatin_m, chLatin_y, chSpace,
	chLatin_S, chLatin_e, chLatin_x, chLatin_p, chDigit_1, chNull
};

XMLCh s_tstSexp2[] = {

	chLatin_D, chLatin_u, chLatin_m, chLatin_m, chLatin_y, chSpace,
	chLatin_S, chLatin_e, chLatin_x, chLatin_p, chDigit_2, chNull
};

XMLCh s_tstMgmtData[] = {

	chLatin_D, chLatin_u, chLatin_m, chLatin_m, chLatin_y, chSpace,
	chLatin_M, chLatin_g, chLatin_m, chLatin_t, chSpace,
	chLatin_D, chLatin_a, chLatin_t, chLatin_a, chNull

};

// --------------------------------------------------------------------------------
//           Find a node
// --------------------------------------------------------------------------------

DOMNode * findNode(DOMNode * n, XMLCh * name) {

	if (XMLString::compareString(name, n->getNodeName()) == 0)
		return n;

	DOMNode * c = n->getFirstChild();

	while (c != NULL) {

		if (c->getNodeType() == DOMNode::ELEMENT_NODE) {

			DOMNode * s = findNode(c, name);
			if (s != NULL)
				return s;

		}

		c = c->getNextSibling();

	}

	return NULL;

}

// --------------------------------------------------------------------------------
//           Create a key
// --------------------------------------------------------------------------------

XSECCryptoKeyHMAC * createHMACKey(const unsigned char * str) {

	// Create the HMAC key
	static bool first = true;

#if defined (HAVE_OPENSSL)
	OpenSSLCryptoKeyHMAC * hmacKey = new OpenSSLCryptoKeyHMAC();
	if (first) {
		cerr << "Using OpenSSL as the cryptography provider" << endl;
		first = false;
	}
#else
#	if defined (HAVE_WINCAPI)
	WinCAPICryptoKeyHMAC * hmacKey = new WinCAPICryptoKeyHMAC();
	if (first) {
		cerr << "Using Windows Crypto API as the cryptography provider" << endl;
		first = false;
	}
#	endif
#endif
	hmacKey->setKey((unsigned char *) str, strlen((char *)str));

	return hmacKey;

}

// --------------------------------------------------------------------------------
//           Utility function for outputting hex data
// --------------------------------------------------------------------------------

void outputHex(unsigned char * buf, int len) {

	cout << std::hex;
	for (int i = 0; i < len; ++i) {
		cout << "0x" << (unsigned int) buf[i] << ", ";
	}
	cout << std::ios::dec << endl;

}

// --------------------------------------------------------------------------------
//           Create a basic document
// --------------------------------------------------------------------------------

DOMDocument * createTestDoc(DOMImplementation * impl) {

	DOMDocument *doc = impl->createDocument(
				0,                    // root element namespace URI.
				MAKE_UNICODE_STRING("ADoc"),            // root element name
				NULL);// DOMDocumentType());  // document type object (DTD).

	DOMElement *rootElem = doc->getDocumentElement();
	rootElem->setAttributeNS(DSIGConstants::s_unicodeStrURIXMLNS, 
		MAKE_UNICODE_STRING("xmlns:foo"), MAKE_UNICODE_STRING("http://www.foo.org"));

	DOMElement  * prodElem = doc->createElement(MAKE_UNICODE_STRING("product"));
	rootElem->appendChild(prodElem);

	DOMText    * prodDataVal = doc->createTextNode(MAKE_UNICODE_STRING("XMLSecurityC"));
	prodElem->appendChild(prodDataVal);

	DOMElement  *catElem = doc->createElement(MAKE_UNICODE_STRING("category"));
	rootElem->appendChild(catElem);
	catElem->setAttribute(MAKE_UNICODE_STRING("idea"), MAKE_UNICODE_STRING("great"));

	DOMText    *catDataVal = doc->createTextNode(MAKE_UNICODE_STRING("XML Security Tools"));
	catElem->appendChild(catDataVal);

	return doc;

}
// --------------------------------------------------------------------------------
//           Output a document if so required
// --------------------------------------------------------------------------------

void outputDoc(DOMImplementation * impl, DOMDocument * doc) {

	if (g_printDocs == false)
		return;

	DOMWriter         *theSerializer = ((DOMImplementationLS*)impl)->createDOMWriter();

	theSerializer->setEncoding(MAKE_UNICODE_STRING("UTF-8"));
	if (theSerializer->canSetFeature(XMLUni::fgDOMWRTFormatPrettyPrint, false))
		theSerializer->setFeature(XMLUni::fgDOMWRTFormatPrettyPrint, false);


	XMLFormatTarget *formatTarget = new StdOutFormatTarget();

	theSerializer->writeNode(formatTarget, *doc);
	
	cout << endl;

	delete theSerializer;
	delete formatTarget;

}

// --------------------------------------------------------------------------------
//           Basic tests of signature function
// --------------------------------------------------------------------------------

void testSignature(DOMImplementation *impl) {

	cerr << "Creating a known doc and signing (HMAC-SHA1)" << endl;
	
	// Create a document
    
	DOMDocument * doc = createTestDoc(impl);

	// Check signature functions

	XSECProvider prov;
	DSIGSignature *sig;
	DSIGReference *ref[10];
	DOMElement *sigNode;
	int refCount;

	try {
		
		/*
		 * Now we have a document, create a signature for it.
		 */
		
		sig = prov.newSignature();
		sig->setDSIGNSPrefix(MAKE_UNICODE_STRING("ds"));
		sig->setPrettyPrint(true);

		sigNode = sig->createBlankSignature(doc, CANON_C14N_COM, SIGNATURE_HMAC, HASH_SHA1);
		DOMElement * rootElem = doc->getDocumentElement();
		DOMNode * prodElem = rootElem->getFirstChild();

		rootElem->appendChild(doc->createTextNode(DSIGConstants::s_unicodeStrNL));
		rootElem->insertBefore(doc->createComment(MAKE_UNICODE_STRING(" a comment ")), prodElem);
		rootElem->appendChild(sigNode);
		rootElem->insertBefore(doc->createTextNode(DSIGConstants::s_unicodeStrNL), prodElem);

		/*
		 * Add some test references
		 */

		ref[0] = sig->createReference(MAKE_UNICODE_STRING(""));
		ref[0]->appendEnvelopedSignatureTransform();

		ref[1] = sig->createReference(MAKE_UNICODE_STRING("#xpointer(/)"));
		ref[1]->appendEnvelopedSignatureTransform();
		ref[1]->appendCanonicalizationTransform(CANON_C14N_NOC);

		ref[2] = sig->createReference(MAKE_UNICODE_STRING("#xpointer(/)"));
		ref[2]->appendEnvelopedSignatureTransform();
		ref[2]->appendCanonicalizationTransform(CANON_C14N_COM);

		ref[3] = sig->createReference(MAKE_UNICODE_STRING("#xpointer(/)"));
		ref[3]->appendEnvelopedSignatureTransform();
		ref[3]->appendCanonicalizationTransform(CANON_C14NE_NOC);

		ref[4] = sig->createReference(MAKE_UNICODE_STRING("#xpointer(/)"));
		ref[4]->appendEnvelopedSignatureTransform();
		ref[4]->appendCanonicalizationTransform(CANON_C14NE_COM);

		ref[5] = sig->createReference(MAKE_UNICODE_STRING("#xpointer(/)"));
		ref[5]->appendEnvelopedSignatureTransform();
		DSIGTransformC14n * ce = ref[5]->appendCanonicalizationTransform(CANON_C14NE_COM);
		ce->addInclusiveNamespace("foo");

		sig->setECNSPrefix(MAKE_UNICODE_STRING("ec"));
		ref[6] = sig->createReference(MAKE_UNICODE_STRING("#xpointer(/)"));
		ref[6]->appendEnvelopedSignatureTransform();
		ce = ref[6]->appendCanonicalizationTransform(CANON_C14NE_COM);
		ce->addInclusiveNamespace("foo");

#ifdef XSEC_NO_XALAN

		cerr << "WARNING : No testing of XPath being performed as Xalan not present" << endl;
		refCount = 7;

#else
		/*
		 * Create some XPath/XPathFilter references
		 */


		ref[7] = sig->createReference(MAKE_UNICODE_STRING(""));
		sig->setXPFNSPrefix(MAKE_UNICODE_STRING("xpf"));
		DSIGTransformXPathFilter * xpf = ref[7]->appendXPathFilterTransform();
		xpf->appendFilter(FILTER_INTERSECT, MAKE_UNICODE_STRING("//ADoc/category"));

		ref[8] = sig->createReference(MAKE_UNICODE_STRING(""));
		/*		ref[5]->appendXPathTransform("ancestor-or-self::dsig:Signature", 
				"xmlns:dsig=http://www.w3.org/2000/09/xmldsig#"); */

		DSIGTransformXPath * x = ref[8]->appendXPathTransform("count(ancestor-or-self::dsig:Signature | \
here()/ancestor::dsig:Signature[1]) > \
count(ancestor-or-self::dsig:Signature)");
		x->setNamespace("dsig", "http://www.w3.org/2000/09/xmldsig#");

		refCount = 9;

#endif
	
		/*
		 * Sign the document, using an HMAC algorithm and the key "secret"
		 */


		sig->appendKeyName(MAKE_UNICODE_STRING("The secret key is \"secret\""));

		// Append a test DNames

		DSIGKeyInfoX509 * x509 = sig->appendX509Data();
		x509->setX509SubjectName(s_tstDName);

		// Append a test PGPData element
		sig->appendPGPData(s_tstPGPKeyID, s_tstPGPKeyPacket);

		// Append an SPKIData element
		DSIGKeyInfoSPKIData * spki = sig->appendSPKIData(s_tstSexp1);
		spki->appendSexp(s_tstSexp2);

		// Append a MgmtData element
		sig->appendMgmtData(s_tstMgmtData);

		sig->setSigningKey(createHMACKey((unsigned char *) "secret"));
		sig->sign();

		cerr << "Doc signed OK - Checking values against Known Good" << endl;

		unsigned char buf[128];
		int len;

		/*
		 * Validate the reference hash values from known good
		 */

		int i;
		for (i = 0; i < refCount; ++i) {

			cerr << "Calculating hash for reference " << i << " ... ";

			len = (int) ref[i]->calculateHash(buf, 128);

			cerr << " Done\nChecking -> ";

			if (len != 20) {
				cerr << "Bad (Length = " << len << ")" << endl;
				exit (1);
			}

			for (int j = 0; j < 20; ++j) {

				if (buf[j] != createdDocRefs[i][j]) {
					cerr << "Bad at location " << j << endl;
					exit (1);
				}
			
			}
			cerr << "Good.\n";

		}

		/*
		 * Verify the signature check works
		 */

		cerr << "Running \"verifySignatureOnly()\" on calculated signature ... ";
		if (sig->verifySignatureOnly()) {
			cerr << "OK" << endl;
		}
		else {
			cerr << "Failed" << endl;
			char * e = XMLString::transcode(sig->getErrMsgs());
			cout << e << endl;
			delete [] e;
			exit(1);
		}

		/*
		 * Change the document and ensure the signature fails.
		 */

		cerr << "Setting incorrect key in Signature object" << endl;
		sig->setSigningKey(createHMACKey((unsigned char *) "badsecret"));

		cerr << "Running \"verifySignatureOnly()\" on calculated signature ... ";
		if (!sig->verifySignatureOnly()) {
			cerr << "OK (Signature bad)" << endl;
		}
		else {
			cerr << "Failed (signature OK but should be bad)" << endl;
			exit(1);
		}

		// Don't need the signature now the DOM structure is in place
		prov.releaseSignature(sig);

		/*
		 * Now serialise the document to memory so we can re-parse and check from scratch
		 */

		cerr << "Serialising the document to a memory buffer ... ";

		DOMWriter         *theSerializer = ((DOMImplementationLS*)impl)->createDOMWriter();

		theSerializer->setEncoding(MAKE_UNICODE_STRING("UTF-8"));
		if (theSerializer->canSetFeature(XMLUni::fgDOMWRTFormatPrettyPrint, false))
			theSerializer->setFeature(XMLUni::fgDOMWRTFormatPrettyPrint, false);


		MemBufFormatTarget *formatTarget = new MemBufFormatTarget();

		theSerializer->writeNode(formatTarget, *doc);

		// Copy to a new buffer
		len = formatTarget->getLen();
		char * mbuf = new char [len + 1];
		memcpy(mbuf, formatTarget->getRawBuffer(), len);
		mbuf[len] = '\0';
#if 0
		cout << mbuf << endl;
#endif
		delete theSerializer;
		delete formatTarget;

		cerr << "done\nParsing memory buffer back to DOM ... ";

		// Also release the document so that we can re-load from scratch

		doc->release();

		/*
		 * Re-parse
		 */

		XercesDOMParser parser;
		
		parser.setDoNamespaces(true);
		parser.setCreateEntityReferenceNodes(true);

		MemBufInputSource* memIS = new MemBufInputSource ((const XMLByte*) mbuf, 
																len, "XSECMem");

		parser.parse(*memIS);
		doc = parser.adoptDocument();


		delete(memIS);
		delete[] mbuf;

		cerr << "done\nValidating signature ...";

		/*
		 * Validate signature
		 */

		sig = prov.newSignatureFromDOM(doc);
		sig->load();
		sig->setSigningKey(createHMACKey((unsigned char *) "secret"));

		if (sig->verify()) {
			cerr << "OK" << endl;
		}
		else {
			cerr << "Failed\n" << endl;
			char * e = XMLString::transcode(sig->getErrMsgs());
			cerr << e << endl;
			delete [] e;
			exit(1);
		}

		/*
		 * Ensure DNames are read back in and decoded properly
		 */

		DSIGKeyInfoList * kil = sig->getKeyInfoList();
		int nki = kil->getSize();

		cerr << "Checking Distinguished name is decoded correctly ... ";
		for (i = 0; i < nki; ++i) {

			if (kil->item(i)->getKeyInfoType() == DSIGKeyInfo::KEYINFO_X509) {

				if (strEquals(s_tstDName, ((DSIGKeyInfoX509 *) kil->item(i))->getX509SubjectName())) {
					cerr << "yes" << endl;
				}
				else {
					cerr << "decoded incorrectly" << endl;;
					exit (1);
				}
			}
			if (kil->item(i)->getKeyInfoType() == DSIGKeyInfo::KEYINFO_PGPDATA) {
				
				cerr << "Validating PGPData read back OK ... ";

				DSIGKeyInfoPGPData * p = (DSIGKeyInfoPGPData *)kil->item(i);

				if (!(strEquals(p->getKeyID(), s_tstPGPKeyID) &&
					strEquals(p->getKeyPacket(), s_tstPGPKeyPacket))) {

					cerr << "no!";
					exit(1);
				}

				cerr << "yes\n";
			}
			if (kil->item(i)->getKeyInfoType() == DSIGKeyInfo::KEYINFO_SPKIDATA) {
				
				cerr << "Validating SPKIData read back OK ... ";

				DSIGKeyInfoSPKIData * s = (DSIGKeyInfoSPKIData *)kil->item(i);

				if (s->getSexpSize() != 2) {
					cerr << "no - expected two S-expressions";
					exit(1);
				}

				if (!(strEquals(s->getSexp(0), s_tstSexp1) &&
					strEquals(s->getSexp(1), s_tstSexp2))) {

					cerr << "no!";
					exit(1);
				}

				cerr << "yes\n";
			}
			if (kil->item(i)->getKeyInfoType() == DSIGKeyInfo::KEYINFO_MGMTDATA) {
				
				cerr << "Validating MgmtData read back OK ... ";

				DSIGKeyInfoMgmtData * m = (DSIGKeyInfoMgmtData *)kil->item(i);

				if (!strEquals(m->getData(), s_tstMgmtData)) {

					cerr << "no!";
					exit(1);
				}

				cerr << "yes\n";
			}
		}
	}

	catch (XSECException &e)
	{
		cerr << "An error occured during signature processing\n   Message: ";
		char * ce = XMLString::transcode(e.getMsg());
		cerr << ce << endl;
		delete ce;
		exit(1);
		
	}	
	catch (XSECCryptoException &e)
	{
		cerr << "A cryptographic error occured during signature processing\n   Message: "
		<< e.getMsg() << endl;
		exit(1);
	}

	// Output the document post signature if necessary
	outputDoc(impl, doc);

	doc->release();

}

// --------------------------------------------------------------------------------
//           Test encrypt/Decrypt
// --------------------------------------------------------------------------------

void testEncrypt(DOMImplementation *impl) {

	cerr << "Creating a known doc encrypting a portion of it" << endl;
	
	// Create a document
    
	DOMDocument * doc = createTestDoc(impl);
	DOMNode * categoryNode = findNode(doc, MAKE_UNICODE_STRING("category"));
	if (categoryNode == NULL) {

		cerr << "Error finding category node for encryption test" << endl;
		exit(1);

	}

	// Check signature functions

	XSECProvider prov;
	XENCCipher * cipher;

	try {
		
		/*
		 * Now we have a document, find the data node.
		 */

		// Generate a key
		unsigned char randomBuffer[256];

#if defined (HAVE_OPENSSL) 
		if (RAND_status() != 1) {

			cerr << "Warning - OpenSSL random not properly initialised" << endl;

		}

		if (RAND_bytes(randomBuffer, 128) != 1) {

			cerr << "Error - OpenSSL random did not generate data" << endl;
			exit(1);
		}
#endif

		static char keyStr[] = "abcdefghijklmnopqrstuvwx";

		cipher = prov.newCipher(doc);
		cipher->setXENCNSPrefix(MAKE_UNICODE_STRING("xenc"));
		cipher->setPrettyPrint(true);

		// Set a key

		OpenSSLCryptoSymmetricKey * k;
		k = new OpenSSLCryptoSymmetricKey(XSECCryptoSymmetricKey::KEY_3DES_CBC_192);
		k->setKey((unsigned char *) randomBuffer, 24);
		cipher->setKey(k);
	
		// Now encrypt!
		cerr << "Performing 3DES encryption on <category> element ... ";
		cipher->encryptElement((DOMElement *) categoryNode, ENCRYPT_3DES_CBC);

		// Add a KeyInfo
		cerr << "done\nAppending a <KeyName> ... ";
		XENCEncryptedData * encryptedData = cipher->getEncryptedData();
		encryptedData->appendKeyName(s_tstKeyName);
		cerr << "done\nSearching for <category> ... ";

		DOMNode * t = findNode(doc, MAKE_UNICODE_STRING("category"));
		if (t != NULL) {

			cerr << "found!\nError - category is not encrypted" << endl;
			exit(1);

		}
		else
			cerr << "not found (OK - now encrypted)" << endl;

		// Now try to encrypt the Key

		cerr << "Encrypting symmetric key ... " << endl;

		OpenSSLCryptoSymmetricKey * kek;
		kek = new OpenSSLCryptoSymmetricKey(XSECCryptoSymmetricKey::KEY_AES_ECB_128);
		kek->setKey((unsigned char *) keyStr, 16);
		cipher->setKEK(kek);

		XENCEncryptedKey * encryptedKey;
		encryptedKey = cipher->encryptKey(randomBuffer, 24, ENCRYPT_KW_AES128);

		cerr << "done!" << endl;

		encryptedData->appendEncryptedKey(encryptedKey);

		outputDoc(impl, doc);

		// OK - Now we try to decrypt
		// Find the EncryptedData node
		DOMNode * n = findXENCNode(doc, "EncryptedData");

		XENCCipher * cipher2 = prov.newCipher(doc);

		OpenSSLCryptoSymmetricKey * k2;
		k2 = new OpenSSLCryptoSymmetricKey(XSECCryptoSymmetricKey::KEY_AES_ECB_128);
		k2->setKey((unsigned char *) keyStr, 16);
		cipher2->setKEK(k2);

		cerr << "Decrypting ... ";
		cipher2->decryptElement(static_cast<DOMElement *>(n));
		cerr << "done" << endl;

		cerr << "Checking for <category> element ... ";

		t = findNode(doc, MAKE_UNICODE_STRING("category"));

		if (t == NULL) {

			cerr << " not found!\nError - category did not decrypt properly" << endl;
			exit(1);

		}
		else
			cerr << "found" << endl;

		cerr << "Checking <KeyName> element is set correctly ... ";

		encryptedData = cipher2->getEncryptedData();

		if (encryptedData == NULL) {
			cerr << "no - cannot access EncryptedData element" << endl;
			exit(1);
		}

		DSIGKeyInfoList * kil = encryptedData->getKeyInfoList();
		int nki = kil->getSize();
		bool foundNameOK = false;

		for (int i = 0; i < nki; ++i) {

			if (kil->item(i)->getKeyInfoType() == DSIGKeyInfo::KEYINFO_NAME) {

				DSIGKeyInfoName *n = dynamic_cast<DSIGKeyInfoName *>(kil->item(i));
				if (!strEquals(n->getKeyName(), s_tstKeyName)) {
					
					cerr << "no!" << endl;
					exit (1);
				}
				foundNameOK = true;
				break;
			}
		}

		if (foundNameOK == false) {
			cerr << "no!" << endl;
			exit(1);
		}
		else
			cerr << "yes." << endl;

	}
	catch (XSECException &e)
	{
		cerr << "An error occured during signature processing\n   Message: ";
		char * ce = XMLString::transcode(e.getMsg());
		cerr << ce << endl;
		delete ce;
		exit(1);
		
	}	
	catch (XSECCryptoException &e)
	{
		cerr << "A cryptographic error occured during signature processing\n   Message: "
		<< e.getMsg() << endl;
		exit(1);
	}

	outputDoc(impl, doc);
	doc->release();

}

	
// --------------------------------------------------------------------------------
//           Print usage instructions
// --------------------------------------------------------------------------------

void printUsage(void) {

	cerr << "\nUsage: xtest [options]\n\n";
	cerr << "     Where options are :\n\n";
	cerr << "     --help/-h\n";
	cerr << "         This help message\n\n";
	cerr << "     --print-docs/-p\n";
	cerr << "         Print the test documents\n\n";
	cerr << "     --signature-only/-s\n";
	cerr << "         Only run signature tests\n\n";
	cerr << "     --encryption-only/-e\n";
	cerr << "         Only run encryption tests\n\n";

}
// --------------------------------------------------------------------------------
//           Main
// --------------------------------------------------------------------------------

int main(int argc, char **argv) {

	/* We output a version number to overcome a "feature" in Microsoft's memory
	   leak detection */

	cerr << "DSIG Info (Using Apache XML-Security-C Library v" << XSEC_VERSION_MAJOR <<
		"." << XSEC_VERSION_MEDIUM << "." << XSEC_VERSION_MINOR << ")\n";

	// Check parameters
	bool		doEncryptionTest = true;
	bool		doSignatureTest = true;

	int paramCount = 1;

	while (paramCount < argc) {

		if (stricmp(argv[paramCount], "--help") == 0 || stricmp(argv[paramCount], "-h") == 0) {
			printUsage();
			exit(0);
		}
		else if (stricmp(argv[paramCount], "--print-docs") == 0 || stricmp(argv[paramCount], "-p") == 0) {
			g_printDocs = true;
			paramCount++;
		}
		else if (stricmp(argv[paramCount], "--signature-only") == 0 || stricmp(argv[paramCount], "-s") == 0) {
			doEncryptionTest = false;
			paramCount++;
		}
		else if (stricmp(argv[paramCount], "--encryption-only") == 0 || stricmp(argv[paramCount], "-e") == 0) {
			doSignatureTest = false;
			paramCount++;
		}
		else {
			printUsage();
			return 2;
		}
	}


#if defined (_DEBUG) && defined (_MSC_VER)

	// Do some memory debugging under Visual C++

	_CrtMemState s1, s2, s3;

	// At this point we are about to start really using XSEC, so
	// Take a "before" checkpoing

	_CrtMemCheckpoint( &s1 );

#endif

	// First initialise the XML system

	try {

		XMLPlatformUtils::Initialize();
#ifndef XSEC_NO_XALAN
		XPathEvaluator::initialize();
		XalanTransformer::initialize();
#endif
		XSECPlatformUtils::Initialise();

	}
	catch (const XMLException &e) {

		cerr << "Error during initialisation of Xerces" << endl;
		cerr << "Error Message = : "
		     << e.getMessage() << endl;

	}

	{

		// Set up for tests

		XMLCh tempStr[100];
		XMLString::transcode("Core", tempStr, 99);    
		DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(tempStr);

		// Test signature functions
		if (doSignatureTest) {
			cerr << endl << "====================================";
			cerr << endl << "Testing Signature Functions";
			cerr << endl << "====================================";
			cerr << endl << endl;

			testSignature(impl);
		}

		// Test encrypt function
		if (doEncryptionTest) {
			cerr << endl << "====================================";
			cerr << endl << "Testing Encryption Function";
			cerr << endl << "====================================";
			cerr << endl << endl;

			testEncrypt(impl);
		}

		cerr << endl << "All tests passed" << endl;

	}

	XSECPlatformUtils::Terminate();
#ifndef XSEC_NO_XALAN
	XalanTransformer::terminate();
	XPathEvaluator::terminate();
#endif
	XMLPlatformUtils::Terminate();

#if defined (_DEBUG) && defined (_MSC_VER)

	_CrtMemCheckpoint( &s2 );

	if ( _CrtMemDifference( &s3, &s1, &s2 ) && (
		s3.lCounts[0] > 0 ||
		s3.lCounts[1] > 1 ||
		// s3.lCounts[2] > 2 ||  We don't worry about C Runtime
		s3.lCounts[3] > 0 ||
		s3.lCounts[4] > 0)) {

		// Note that there is generally 1 Normal and 1 CRT block
		// still taken.  1 is from Xalan and 1 from stdio

		// Send all reports to STDOUT
		_CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE );
		_CrtSetReportFile( _CRT_WARN, _CRTDBG_FILE_STDOUT );
		_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_FILE );
		_CrtSetReportFile( _CRT_ERROR, _CRTDBG_FILE_STDOUT );
		_CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE );
		_CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDOUT );

		// Dumpy memory stats

 		_CrtMemDumpAllObjectsSince( &s3 );
	    _CrtMemDumpStatistics( &s3 );
	}

	// Now turn off memory leak checking and end as there are some 
	// Globals that are allocated that get seen as leaks (Xalan?)

	int dbgFlag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
	dbgFlag &= ~(_CRTDBG_LEAK_CHECK_DF);
	_CrtSetDbgFlag( dbgFlag );

#endif


	return 0;

}
