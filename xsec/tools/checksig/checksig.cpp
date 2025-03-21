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
 * checkSig := (Very ugly) tool to check a signature embedded in an XML file
 *
 * $Id$
 *
 */

#include "AnonymousResolver.hpp"
#include "InteropResolver.hpp"

// XSEC

#include <xsec/utils/XSECPlatformUtils.hpp>
#include <xsec/framework/XSECProvider.hpp>
#include <xsec/canon/XSECC14n20010315.hpp>
#include <xsec/dsig/DSIGSignature.hpp>
#include <xsec/framework/XSECException.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>

#include "../../utils/XSECDOMUtils.hpp"

// General

#include <memory.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>

#if defined(HAVE_UNISTD_H)
# include <unistd.h>
#else
# if defined(HAVE_DIRECT_H)
#  include <direct.h>
# endif
#endif

#if defined (_DEBUG) && defined (_MSC_VER)
#include <crtdbg.h>
#endif


#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/util/XMLString.hpp>

#include <xercesc/dom/DOM.hpp>
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/util/XMLException.hpp>
#include <xercesc/util/XMLUri.hpp>
#include <xercesc/util/Janitor.hpp>

XERCES_CPP_NAMESPACE_USE

using std::cerr;
using std::cout;
using std::endl;

#if defined (XSEC_HAVE_OPENSSL)
// OpenSSL

#	include <xsec/enc/OpenSSL/OpenSSLCryptoKeyHMAC.hpp>
#	include <openssl/err.h>

#endif

#include <time.h>

std::ostream& operator<< (std::ostream& target, const XMLCh * s)
{
    char *p = XMLString::transcode(s);
    target << p;
    XSEC_RELEASE_XMLCH(p);
    return target;
}

// ----------------------------------------------------------------------------
//           Checksig
// ----------------------------------------------------------------------------


void printUsage(void) {

	cerr << "\nUsage: checksig [options] <input file name>\n\n";
	cerr << "     Where options are :\n\n";
	cerr << "     --skiprefs/-s\n";
	cerr << "         Skip checking references - check signature only\n\n";
	cerr << "     --hmackey/-h <string>\n";
	cerr << "         Set an hmac key using the <string>\n\n";
	cerr << "     --xsecresolver/-x\n";
	cerr << "         Use the xml-security test XMLDSig URI resolver\n\n";
	cerr << "     --id <name>\n";
	cerr << "         Define an attribute Id by name\n\n";
	cerr << "     --idns/-d <ns uri> <name>\n";
	cerr << "         Define an attribute Id by namespace URI and name\n\n";
#if defined (XSEC_HAVE_OPENSSL)
	cerr << "     --interop/-i\n";
	cerr << "         Use the interop resolver for Baltimore interop examples\n\n";
#endif
	cerr << "     Exits with codes :\n";
	cerr << "         0 = Signature OK\n";
	cerr << "         1 = Signature Bad\n";
	cerr << "         2 = Processing error\n";

}

int evaluate(int argc, char ** argv) {
	
	char					* filename = NULL;
	char					* hmacKeyStr = NULL;
	char					* useIdAttributeNS = NULL;
	char					* useIdAttributeName = NULL;
	XSECCryptoKey			* key = NULL;
	bool					useXSECURIResolver = false;
	bool                    useAnonymousResolver = false;
	bool					useInteropResolver = false;

	bool skipRefs = false;

	if (argc < 2) {

		printUsage();
		return 2;
	}

	// Run through parameters
	int paramCount = 1;

	while (paramCount < argc - 1) {

		if (_stricmp(argv[paramCount], "--hmackey") == 0 || _stricmp(argv[paramCount], "-h") == 0) {
			paramCount++;
			hmacKeyStr = argv[paramCount++];
		}
		else if (_stricmp(argv[paramCount], "--skiprefs") == 0 || _stricmp(argv[paramCount], "-s") == 0) {
			skipRefs = true;
			paramCount++;
		}
		else if (_stricmp(argv[paramCount], "--xsecresolver") == 0 || _stricmp(argv[paramCount], "-x") == 0) {
			useXSECURIResolver = true;
			paramCount++;
		}
		else if (_stricmp(argv[paramCount], "--id") == 0) {
			if (paramCount +1 >= argc) {
				printUsage();
				return 2;
			}
			paramCount++;
			useIdAttributeName = argv[paramCount++];
		}
		else if (_stricmp(argv[paramCount], "--idns") == 0 || _stricmp(argv[paramCount], "-d") == 0) {
			if (paramCount +2 >= argc) {
				printUsage();
				return 2;
			}
			paramCount++;
			useIdAttributeNS = argv[paramCount++];
			useIdAttributeName = argv[paramCount++];
		}
#if defined (XSEC_HAVE_OPENSSL)
		else if (_stricmp(argv[paramCount], "--interop") == 0 || _stricmp(argv[paramCount], "-i") == 0) {
			// Use the interop key resolver
			useInteropResolver = true;
			paramCount++;
		}
#endif
		else if (_stricmp(argv[paramCount], "--anonymousresolver") == 0 || _stricmp(argv[paramCount], "-a") ==0) {
			useAnonymousResolver = true;
			paramCount++;
		}
		else {
			cerr << "Unknown option: " << argv[paramCount] << endl << endl;
			printUsage();
			return 2;
		}
	}

	if (paramCount >= argc) {
		printUsage();
		return 2;
	}

	filename = argv[paramCount];

	// Create and set up the parser

	XercesDOMParser * parser = new XercesDOMParser;
	Janitor<XercesDOMParser> j_parser(parser);

	parser->setDoNamespaces(true);
	parser->setCreateEntityReferenceNodes(true);

	// Now parse out file

	bool errorsOccured = false;
	XMLSize_t errorCount = 0;
    try
    {
    	parser->parse(filename);
        errorCount = parser->getErrorCount();
        if (errorCount > 0)
            errorsOccured = true;
    }

    catch (const XMLException& e)
    {
        cerr << "An error occurred during parsing\n   Message: "
             << e.getMessage() << endl;
        errorsOccured = true;
    }


    catch (const DOMException& e)
    {
       cerr << "A DOM error occurred during parsing\n   DOMException code: "
             << e.code << endl;
        errorsOccured = true;
    }

	if (errorsOccured) {

		cout << "Errors during parse" << endl;
		return (2);

	}

	/*

		Now that we have the parsed file, get the DOM document and start looking at it

	*/
	
	DOMNode *doc;		// The document that we parsed

	doc = parser->getDocument();
	DOMDocument *theDOM = parser->getDocument();

	// Find the signature node
	
	DOMNode *sigNode = findDSIGNode(doc, "Signature");

	// Create the signature checker

	if (sigNode == 0) {

		cerr << "Could not find <Signature> node in " << argv[argc-1] << endl;
		return 2;
	}

	XSECProvider prov;
	XSECKeyInfoResolverDefault theKeyInfoResolver;

	DSIGSignature * sig = prov.newSignatureFromDOM(theDOM, sigNode);

	// The only way we can verify is using keys read directly from the KeyInfo list,
	// so we add a KeyInfoResolverDefault to the Signature.

	sig->setKeyInfoResolver(&theKeyInfoResolver);

	// Register defined attribute name
	if (useIdAttributeName != NULL) {
        sig->setIdByAttributeName(true);
        if (useIdAttributeNS != NULL) {
		    sig->registerIdAttributeNameNS(MAKE_UNICODE_STRING(useIdAttributeNS), 
									       MAKE_UNICODE_STRING(useIdAttributeName));
        } else {
            sig->registerIdAttributeName(MAKE_UNICODE_STRING(useIdAttributeName));
        }
    }

	// Check whether we should use the internal resolver

	
	if (useXSECURIResolver == true || 
		useAnonymousResolver == true ||
		useInteropResolver == true) {

		AnonymousResolver theAnonymousResolver;
		     
		// Map out base path of the file
#if XSEC_HAVE_GETCWD_DYN
		char *path = getcwd(NULL, 0);
		char *baseURI = (char*)malloc(strlen(path) + 8 + 1 + strlen(filename) + 1);
#else
		char path[PATH_MAX];
		char baseURI[(PATH_MAX * 2) + 10];
		getcwd(path, PATH_MAX);
#endif
		strcpy(baseURI, "file:///");		

		// Ugly and nasty but quick
		if (filename[0] != '\\' && filename[0] != '/' && filename[1] != ':') {
			strcat(baseURI, path);
			strcat(baseURI, "/");
		} else if (path[1] == ':') {
			path[2] = '\0';
			strcat(baseURI, path);
		}

		strcat(baseURI, filename);

		// Find any ':' and "\" characters
		int lastSlash = 0;
		for (unsigned int i = 8; i < strlen(baseURI); ++i) {
			if (baseURI[i] == '\\') {
				lastSlash = i;
				baseURI[i] = '/';
			}
			else if (baseURI[i] == '/')
				lastSlash = i;
		}

		// The last "\\" must prefix the filename
		baseURI[lastSlash + 1] = '\0';
		XMLCh * baseURIXMLCh = XMLString::transcode(baseURI);

		XMLUri uri(MAKE_UNICODE_STRING(baseURI));
#if XSEC_HAVE_GETCWD_DYN
		free(path);
		free(baseURI);
#endif

		if (useAnonymousResolver == true) {
			sig->setURIResolver(&theAnonymousResolver);
		}
        sig->getURIResolver()->setBaseURI(baseURIXMLCh);

#if defined (XSEC_HAVE_OPENSSL)
		if (useInteropResolver == true) {
			InteropResolver ires(&(baseURIXMLCh[8]));
			sig->setKeyInfoResolver(&ires);
		}
#endif
		XSEC_RELEASE_XMLCH(baseURIXMLCh);
	}

	bool result;

	try {

		// Load a key if necessary
		if (hmacKeyStr != NULL) {

			XSECCryptoKeyHMAC * hmacKey = XSECPlatformUtils::g_cryptoProvider->keyHMAC();
			hmacKey->setKey((unsigned char *) hmacKeyStr, (unsigned int) strlen(hmacKeyStr));
			sig->setSigningKey(hmacKey);

		}
		else if (key != NULL) {

			sig->setSigningKey(key);

		}

		sig->load();
		if (skipRefs)
			result = sig->verifySignatureOnly();
		else
			result = sig->verify();
	}

	catch (const XSECException &e) {
		char * msg = XMLString::transcode(e.getMsg());
		cerr << "An error occurred during signature verification\n   Message: "
		<< msg << endl;
		XSEC_RELEASE_XMLCH(msg);
		errorsOccured = true;
		return 2;
	}
	catch (const XSECCryptoException &e) {
		cerr << "An error occurred during signature verification\n   Message: "
		<< e.getMsg() << endl;
		errorsOccured = true;

#if defined (XSEC_HAVE_OPENSSL)
		ERR_load_crypto_strings();
		BIO * bio_err;
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

		ERR_print_errors(bio_err);
#endif
		return 2;
	}

#if 0
	catch (...) {

		cerr << "Unknown Exception type occurred.  Cleaning up and exiting\n" << endl;

		return 2;

	}
#endif
	int retResult;


	if (result) {
		cout << "Signature verified OK!" << endl;
		retResult = 0;
	}
	else {
		cout << "Signature failed verification" << endl;
		char * e = XMLString::transcode(sig->getErrMsgs());
		cout << e << endl;
		XSEC_RELEASE_XMLCH(e);
		retResult = 1;
	}

	// Janitor will clean up the parser
	return retResult;

}


int main(int argc, char **argv) {

	int retResult;

#if defined (_DEBUG) && defined (_MSC_VER)

	// Do some memory debugging under Visual C++

	_CrtMemState s1, s2, s3;

	// At this point we are about to start really using XSEC, so
	// Take a "before" checkpoing

	_CrtMemCheckpoint( &s1 );

#endif

	// Initialise the XML system

	try {

		XMLPlatformUtils::Initialize();
		XSECPlatformUtils::Initialise();

	}
	catch (const XMLException &e) {

		cerr << "Error during initialisation of Xerces" << endl;
		cerr << "Error Message = : "
		     << e.getMessage() << endl;

	}

	retResult = evaluate(argc, argv);

	XSECPlatformUtils::Terminate();
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

	return retResult;
}
