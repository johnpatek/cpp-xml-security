/*
 * The Apache Software License, Version 1.1
 *
 *
 * Copyright (c) 1999 The Apache Software Foundation.  All rights 
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
 * InteropResolver := Class to resolve key elements into certificates for
 *						merlin-18 interop test
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

// XSEC

#include "InteropResolver.hpp"

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/enc/XSECKeyInfoResolver.hpp>
#include <xsec/dsig/DSIGKeyInfoX509.hpp>
#include <xsec/dsig/DSIGKeyInfoName.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
#include <xsec/utils/XSECDOMUtils.hpp>

#include <xsec/enc/OpenSSL/OpenSSLCryptoBase64.hpp>

#include <xercesc/util/Janitor.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

XSEC_USING_XERCES(ArrayJanitor);

#include <iostream>

InteropResolver::InteropResolver(const XMLCh * baseURI) {

	if (baseURI != NULL)
		mp_baseURI = XMLString::replicate(baseURI);
	else
		mp_baseURI = NULL;

	m_searchStarted = false;
	m_searchFinished = false;

#if !defined(_WIN32)
	m_fcount = 0;
#endif

}


InteropResolver::~InteropResolver() {

	if (mp_baseURI != NULL)
		delete[]mp_baseURI;

}

#if defined(_WIN32)

void reverseSlash(safeBuffer &path) {

	for (int i = 0; i < strlen(path.rawCharBuffer()); ++i) {

		if (path[i] == '/')
			path[i] = '\\';

	}

}

#endif


X509 * InteropResolver::nextFile2Cert(void) {


	if (m_searchFinished)
		return NULL;

	int res;

	if (!m_searchStarted) {

		char * base = XMLString::transcode(mp_baseURI);
		safeBuffer path = base;
		delete[] base;

		path.sbStrcatIn("/certs/*.crt");

#if defined(_WIN32)

		// Reverse the "backslash" characters

		reverseSlash(path);

		m_handle = _findfirst(path.rawCharBuffer(), &m_finder);
		res = m_handle;
#else
		if (glob(path.rawCharBuffer(), 0, NULL, &m_globbuf) != 0)
			res = -1;
		else
			res = 0;
#endif

		m_searchStarted = true;

	}
	else {

#if defined(_WIN32)
		res = _findnext(m_handle, &m_finder);
#else
		if (m_fcount == m_globbuf.gl_pathc)
			res = -1;
		else
			res = 0;
#endif

	}

	if (res == -1) {

		m_searchFinished = true;
		return NULL;

	}

	/* 
	 * Create the OpenSSL BIOs necessary to read in the X509 cert
	 */

	BIO * bioCert;
	if ((bioCert = BIO_new(BIO_s_file())) == NULL) {

		std::cerr << "Error opening certificate file\n\n";
		exit (1);

	}

	// Create the filename
	safeBuffer fname;
#if defined(_WIN32)
	fname.sbTranscodeIn(mp_baseURI);
	fname.sbStrcatIn("/certs/");
	fname.sbStrcatIn(m_finder.name);
	reverseSlash(fname);
#else
	fname.sbStrcpyIn(m_globbuf.gl_pathv[m_fcount++]);
#endif

	if (BIO_read_filename(bioCert, fname.rawCharBuffer()) <= 0) {

		std::cerr << "Error opening certificate file\n" << fname.rawCharBuffer() << std::endl;
		return NULL;

	}

	X509 * x509 = d2i_X509_bio(bioCert, NULL);
	BIO_free(bioCert);

	return x509;


}

X509_NAME * X509_NAME_create_from_txt(const char * n) {

	// I'm sure there must be a function to do this in OpenSSL, but I'm
	// darned if I can find it.

	int idx = 0;
	int j;
	bool ok = true;

	X509_NAME_ENTRY * entries[10];
	int entCount = 0;

	char * name = new char[strlen(n)];
	char * value = new char[strlen(n)];
	while (true) {

		while (n[idx] == ' ' ||
			   n[idx] == '\t' ||
			   n[idx] == '\n' ||
			   n[idx] == '\r')
			   idx++;
		
		if (n[idx] == 0)
			break;

		j = 0;
		while (n[idx] != 0 && n[idx] != '=') {
			name[j++] = n[idx++];
		}

		if (j == 0 || n[idx] == 0) {
			ok = false;
			break;
		}

		name[j] = '\0';
		idx++;

		// Now the value
		j = 0;
		while (n[idx] != 0 && (n[idx] != ',' || n[idx-1] == '\\') && 
			n[idx] != '\n' && n[idx] != '\r') {
			if (n[idx] != '\\')
				value[j++] = n[idx++];
			else
				idx++;
		}

		if (j == 0) {
			ok = false;
			break;
		}

		if (n[idx] != 0)
			idx++;

		value[j] = '\0';
		X509_NAME_ENTRY * xne;

		xne = X509_NAME_ENTRY_create_by_txt(NULL, name, MBSTRING_ASC, (unsigned char *) value, -1);

		if (xne != NULL) {
			entries[entCount++] = xne;
			if (entCount == 10) {
				ok = false;
				break;
			}
		}
		else {
			ok = false;
			break;
		}

	}

	delete[] name;
	delete[] value;

	X509_NAME *ret = NULL;
	int i;

	if (ok) {

		// Create the return value
		ret = X509_NAME_new();
		for (i = entCount - 1; i >= 0; --i) {

			if (!X509_NAME_add_entry(ret, entries[i], -1, 0)) {
				X509_NAME_free(ret);
				ret = NULL;
				break;
			}
		}

	}
	
	// Clean out the entries
	for (i = 0; i < entCount; ++i) {
		X509_NAME_ENTRY_free(entries[i]);
	}

	return ret;
}

bool InteropResolver::checkMatch(DSIGKeyInfoList * lst, X509 * x) {

	// Check if the parameters in x match the required certificate


	int sz = lst->getSize();
	DSIGKeyInfo* k;
	
	for (int i = 0; i < sz; ++i) {

		k = lst->item(i);

		if (k->getKeyInfoType() == DSIGKeyInfo::KEYINFO_X509) {

			DSIGKeyInfoX509 * kx = static_cast<DSIGKeyInfoX509 *>(k);
			
			const XMLCh * serial = kx->getX509IssuerSerialNumber();

			if (serial != NULL) {

				char * cserial = XMLString::transcode(serial);
				char * xserial;

				BIGNUM * bnserial = ASN1_INTEGER_to_BN(x->cert_info->serialNumber, NULL);
				xserial = BN_bn2dec(bnserial);
				BN_free(bnserial);

				if (strcmp(xserial, cserial) == 0) {
					
					OPENSSL_free(xserial);
					delete[] cserial;
					return true;

				}
				//delete[] xserial;
				delete[] cserial;
				OPENSSL_free(xserial);

			}

			/* 
			 * Either it's not a serial number, or we didn't pass, so lets
			 * look at the next option.
			 */
			
			const XMLCh * ski = kx->getX509SKI();
			
			if (ski != NULL) {

				char * cski = XMLString::transcode(ski);
				int clen = strlen(cski);
				unsigned char * xski = new unsigned char[clen];
				ArrayJanitor<char> j_cski(cski);
				ArrayJanitor <unsigned char> j_xski(xski);

				// Decode

				OpenSSLCryptoBase64 b64;
				b64.decodeInit();
				int xlen = b64.decode((unsigned char *) cski, clen, xski, clen);
				xlen += b64.decodeFinish(&xski[xlen], clen - xlen);

				if (xlen != 0) {

					// Have a buffer with a number in it
					STACK_OF(X509_EXTENSION) *exts;
					exts = x->cert_info->extensions;

					if (exts != NULL) {

						// Find the Subject Key Identifier OID
						X509_EXTENSION * ext;
						ASN1_OBJECT * objski = OBJ_nid2obj(NID_subject_key_identifier);
						int extn = X509v3_get_ext_by_OBJ(exts, objski, -1);
						if (extn != -1) {
							// Dummy up an OCTET_STRING from the xski
							unsigned char * octxski = new unsigned char[xlen + 2];
							ArrayJanitor<unsigned char> j_octxski(octxski);

							octxski[0] = 4;
							octxski[1] = xlen;
							memcpy(&octxski[2], xski, xlen);
							
							ext = sk_X509_EXTENSION_value(exts,extn);
							ASN1_OCTET_STRING *skid = ext->value;
							ASN1_OCTET_STRING * xskid = M_ASN1_OCTET_STRING_new();
							ASN1_STRING_set(xskid, octxski, xlen+2);
							
							if (ASN1_OCTET_STRING_cmp(xskid, skid) == 0) {
								ASN1_OCTET_STRING_free(xskid);
								return true;
							}
						}

					}

				}

			}

			/* Not a subject key identifier */
			const XMLCh *sn = kx->getX509SubjectName();

			if (sn != NULL) {

				char * csn = XMLString::transcode(sn);

				X509_NAME * x509name = X509_get_subject_name(x);
				X509_NAME * snname = X509_NAME_create_from_txt(csn);
				delete[] csn;

				if (snname != NULL) {

					if (!X509_NAME_cmp(x509name, snname)) {
						X509_NAME_free(snname);
						return true;
					}
				
					X509_NAME_free(snname);
				}
			}
		}
	}

	return false;

}


XSECCryptoKey * InteropResolver::openCertURI(const XMLCh * uri) {

	// Open a certificate from a file URI relative to the signature file
	BIO * bioCert;
	if ((bioCert = BIO_new(BIO_s_file())) == NULL) {
		
		return NULL;

	}

	safeBuffer fname;
	char * u = XMLString::transcode(uri);
	ArrayJanitor<char> j_u(u);
	fname.sbTranscodeIn(mp_baseURI);
	fname.sbStrcatIn("/");
	fname.sbStrcatIn(u);

#if defined(_WIN32)
	reverseSlash(fname);
#endif

	if (BIO_read_filename(bioCert, fname.rawCharBuffer()) <= 0) {
		
		return NULL;

	}

	X509 * x509 = d2i_X509_bio(bioCert, NULL);
	BIO_free(bioCert);

	OpenSSLCryptoX509 oX509(x509);
	X509_free(x509);

	return oX509.clonePublicKey();

}

XSECCryptoKey * InteropResolver::resolveKey(DSIGKeyInfoList * lst) {


	// First check if this has an X509 cert + an X509 CRL
	const XMLCh * b64cert = NULL;
	const XMLCh * b64crl = NULL;

	int lstSize = lst->getSize();

	for (int i = 0; i < lstSize; ++i) {

		DSIGKeyInfo * ki;
		ki = lst->item(i);
		const XMLCh * rawuri;

		if (ki->getKeyInfoType() == DSIGKeyInfo::KEYINFO_X509) {
			
			DSIGKeyInfoX509 * kix509 = static_cast<DSIGKeyInfoX509 *>(ki);

			if ((rawuri = kix509->getRawRetrievalURI()) != NULL) {

				// We have a raw certificate by de-reference
				// Assume it is just a file dereference and open the cert

				return openCertURI(rawuri);

			}
			
			if (kix509->getCertificateListSize() == 1) {

				b64cert = kix509->getCertificateItem(0);

			}

			if (b64crl == NULL) {

				b64crl = kix509->getX509CRL();

			}
		}

		else if (ki->getKeyInfoType() == DSIGKeyInfo::KEYINFO_NAME) {

			DSIGKeyInfoName * kn = static_cast<DSIGKeyInfoName *>(ki);

			if (kn->getKeyName() != NULL) {

				static XMLCh certStr[] = {
					XERCES_CPP_NAMESPACE :: chLatin_c,
					XERCES_CPP_NAMESPACE :: chLatin_e,
					XERCES_CPP_NAMESPACE :: chLatin_r,
					XERCES_CPP_NAMESPACE :: chLatin_t,
					XERCES_CPP_NAMESPACE :: chLatin_s,
					XERCES_CPP_NAMESPACE :: chForwardSlash,
					XERCES_CPP_NAMESPACE :: chNull
				};
				static XMLCh extStr[] = {
					XERCES_CPP_NAMESPACE :: chPeriod,
					XERCES_CPP_NAMESPACE :: chLatin_c,
					XERCES_CPP_NAMESPACE :: chLatin_r,
					XERCES_CPP_NAMESPACE :: chLatin_t,
					XERCES_CPP_NAMESPACE :: chNull
				};

				safeBuffer fname;
				fname = certStr;
				fname.sbXMLChCat(kn->getKeyName());
				fname.sbXMLChCat(extStr);

				fname.sbStrlwr();

				return openCertURI(fname.rawXMLChBuffer());

			}

		}

	}

	if (b64cert != NULL && b64crl != NULL) {

		// We have a certificate and a crl, lets get the cert and check in the crl

		OpenSSLCryptoBase64 b64;
		char * transb64cert = XMLString::transcode(b64cert);
		unsigned char * x509buf = new unsigned char[strlen(transb64cert)];
		ArrayJanitor<char> j_transb64cert(transb64cert);
		ArrayJanitor<unsigned char> j_x509buf(x509buf);

		int x509bufLen;

		X509 *x;

		b64.decodeInit();
		x509bufLen = b64.decode((unsigned char *) transb64cert, strlen(transb64cert), x509buf, strlen(transb64cert));
		x509bufLen += b64.decodeFinish(&x509buf[x509bufLen], strlen(transb64cert) - x509bufLen);

		if (x509bufLen > 0) {
			x =  d2i_X509(NULL, &x509buf, x509bufLen);
		}
		else 
			return NULL;		// Something has gone wrong

		if (x == NULL)
			return NULL;

		// Now the CRL
		char * transb64crl = XMLString::transcode(b64crl);
		unsigned char * crlbuf = new unsigned char[strlen(transb64crl)];
		ArrayJanitor<char> j_transb64crl(transb64crl);
		ArrayJanitor<unsigned char> j_crlbuf(crlbuf);

		int crlbufLen;

		X509_CRL * c;

		b64.decodeInit();
		crlbufLen = b64.decode((unsigned char*) transb64crl, strlen(transb64crl), crlbuf, strlen(transb64crl));
		crlbufLen += b64.decodeFinish(&crlbuf[crlbufLen], strlen(transb64crl) - crlbufLen);

		if (crlbufLen > 0) {
			c =  d2i_X509_CRL(NULL, &crlbuf, crlbufLen);
		}
		else 
			return NULL;		// Something has gone wrong

		if (c == NULL)
			return NULL;

		// Now check if the cert is in the CRL (code lifted from OpenSSL x509_vfy.c

        int idx;
        X509_REVOKED rtmp;

        /* Look for serial number of certificate in CRL */
        
		rtmp.serialNumber = X509_get_serialNumber(x);
        idx = sk_X509_REVOKED_find(c->crl->revoked, &rtmp);
        
		/* Not found: OK */
        
		if(idx != -1) {

			std::cerr << "Warning - certificate revoked in attached CRL" << std::endl;

		}

		OpenSSLCryptoX509 ox(x);
		X509_free(x);
		X509_CRL_free(c);
		return ox.clonePublicKey();

	}

	// Do a run through each match in the directory

	while (m_searchFinished == false) {

		X509 * x = nextFile2Cert();

		if (x != NULL) {

			if (checkMatch(lst, x)) {

				OpenSSLCryptoX509 ox(x);
				X509_free(x);
				return ox.clonePublicKey();

			}

		}
		X509_free(x);

	}

	return false;

}



XSECKeyInfoResolver * InteropResolver::clone(void) {

	return new InteropResolver(mp_baseURI);

}


