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
 * siginf := Output information about a signature found in an XML file
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

// XSEC

#include <xsec/utils/XSECPlatformUtils.hpp>
#include <xsec/framework/XSECProvider.hpp>
#include <xsec/canon/XSECC14n20010315.hpp>
#include <xsec/dsig/DSIGSignature.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/framework/XSECException.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>

#include <xsec/dsig/DSIGTransformC14n.hpp>
#include <xsec/dsig/DSIGTransformBase64.hpp>
#include <xsec/dsig/DSIGTransformXSL.hpp>
#include <xsec/dsig/DSIGTransformXPath.hpp>
#include <xsec/dsig/DSIGTransformXPathFilter.hpp>
#include <xsec/dsig/DSIGXPathFilterExpr.hpp>
#include <xsec/dsig/DSIGTransformEnvelope.hpp>

#include <xsec/dsig/DSIGTransformList.hpp>

#include "../../utils/XSECDOMUtils.hpp"

// General

#include <memory.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>

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
using std::ostream;

ostream& operator<< (ostream& target, const XMLCh * s)
{
    char *p = XMLString::transcode(s);
    target << p;
    XSEC_RELEASE_XMLCH(p);
    return target;
}

class X2C {

public:

	X2C(const XMLCh * in) {
		mp_cStr = XMLString::transcode(in);
	}
	~X2C() {
		XSEC_RELEASE_XMLCH(mp_cStr);
	}

	char * str(void) {
		return mp_cStr;
	}

private :

	char * mp_cStr;

};

ostream & operator<<(ostream& target, X2C &x) {
	target << x.str();
	return target;
}

inline
void levelSet(unsigned int level) {

	for (unsigned int i = 0; i < level; ++i)
		cout << "    ";

}

void outputTransform(const DSIGTransform * t, unsigned int level) {


    if (dynamic_cast<const DSIGTransformBase64*>(t)) {
		cout << "Base64 Decode" << endl;
    }
    else if (dynamic_cast<const DSIGTransformC14n*>(t)) {
        const XMLCh* cm = dynamic_cast<const DSIGTransformC14n*>(t)->getCanonicalizationMethod();
        if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIC14N_NOC)) {
            cout << "c14n 1.0 canonicalization (without comments)" << endl;
        }
        else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIC14N_COM)) {
            cout << "c14n 1.0 canonicalization (with comments)" << endl;
        }
        else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIC14N11_NOC)) {
            cout << "c14n 1.1 canonicalization (without comments)" << endl;
        }
        else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIC14N11_COM)) {
            cout << "c14n 1.1 canonicalization (with comments)" << endl;
        }
        else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIEXC_C14N_NOC)) {
            cout << "Exclusive c14n 1.0 canonicalization (without comments)" << endl;
            if (dynamic_cast<const DSIGTransformC14n*>(t)->getPrefixList() != NULL) {
                levelSet(level);
                cout << "Inclusive prefixes : " <<
                    X2C(dynamic_cast<const DSIGTransformC14n*>(t)->getPrefixList()).str() << endl;
            }
        }
        else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIEXC_C14N_COM)) {
            cout << "Exclusive c14n 1.0 canonicalization (with comments)" << endl;
            if (dynamic_cast<const DSIGTransformC14n*>(t)->getPrefixList() != NULL) {
                levelSet(level);
                cout << "Inclusive prefixes : " <<
                    X2C(dynamic_cast<const DSIGTransformC14n*>(t)->getPrefixList()).str() << endl;
            }
        }
        else {
            cout << "Unknown c14n method" << endl;
        }
    }
    else if (dynamic_cast<const DSIGTransformEnvelope*>(t)) {
        cout << "enveloped signature" << endl;
    }
    else if (dynamic_cast<const DSIGTransformXPath*>(t)) {
        const DSIGTransformXPath* xp = dynamic_cast<const DSIGTransformXPath*>(t);

        cout << "XPath" << endl;
        // Check for namespaces
        DOMNamedNodeMap* atts = xp->getNamespaces();

        if (atts != 0) {
            XMLSize_t s = atts->getLength();
            for (XMLSize_t i = 0 ; i < s; ++i) {
                levelSet(level);
                cout << "Namespace : " << X2C(atts->item(i)->getNodeName()).str() <<
                    "=\"" << X2C(atts->item(i)->getNodeValue()).str() << "\"\n";
            }
        }
        levelSet(level);
        // Hmm - this is really a bug.  This should return a XMLCh string
        cout << "Expr : " << xp->getExpression() << endl;
    }
    else if (dynamic_cast<const DSIGTransformXPathFilter*>(t)) {
        const DSIGTransformXPathFilter * xpf = dynamic_cast<const DSIGTransformXPathFilter*>(t);

        cout << "XPath-Filter2" << endl;

        unsigned int s = xpf->getExprNum();

        for (unsigned int i = 0; i < s; ++i) {

            levelSet(level);
            cout << "Filter : ";

            const DSIGXPathFilterExpr * e = xpf->expr(i);

            switch (e->getFilterType()) {

            case DSIGXPathFilterExpr::FILTER_UNION :
                cout << "union : \"";
                break;
            case DSIGXPathFilterExpr::FILTER_INTERSECT :
                cout << "intersect : \"";
                break;
            default :
                cout << "subtract : \"";
            }

            // Now the expression
            char * str = XMLString::transcode(e->getFilter());
            cout << str << "\"" << endl;
            XSEC_RELEASE_XMLCH(str);
        }
    }
    else if (dynamic_cast<const DSIGTransformXSL*>(t)) {
        cout << "XSLT" << endl;
        // Really should serialise and output stylesheet.
    }
    else {
		cout << "unknown transform type" << endl;
    }
}
		
void outputReferences(DSIGReferenceList *rl, unsigned int level) {

	int s = (int) rl->getSize();

	for (int i = 0; i < s; ++i) {
	
		levelSet(level);
		cout << "Reference " << i + 1 << " : " << endl;
		levelSet(level + 1);
		cout << "URI : \"" << X2C(rl->item(i)->getURI()).str() << "\"" << endl;
		levelSet(level + 1);
		cout << "Digest Algorithm : ";
        char* alg = XMLString::transcode(rl->item(i)->getAlgorithmURI());
        cout << (alg ? alg : "Unknown") << endl;
        XSEC_RELEASE_XMLCH(alg);

		// Now the transforms
		DSIGTransformList * tl = rl->item(i)->getTransforms();
		if (tl != NULL) {

			int tlSize = (int) tl->getSize();
			for (int j = 0 ; j < tlSize; ++j) {

				levelSet(level+1);
				cout << "Transform " << j + 1 << " : ";
				outputTransform(tl->item(j), level + 2);

			}

		}

		if (rl->item(i)->isManifest() == true) {

			levelSet(level + 1);
			cout << "Manifest References : " << endl;
			outputReferences(rl->item(i)->getManifestReferenceList(), level + 2);
			levelSet(level + 1);
			cout << "End Manifest References" << endl;

		}

	}

}

void outputSignatureInfo(DSIGSignature *sig, bool skipReferences) {

	// First get some information about the main signature
	cout << "Signature (Signed Info) settings : " << endl;
	cout << "    Canonicalization Method : ";
	
    const XMLCh* cm = sig->getCanonicalizationMethod();
    if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIC14N_NOC)) {
        cout << "c14n 1.0 canonicalization (without comments)" << endl;
    }
    else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIC14N_COM)) {
        cout << "c14n 1.0 canonicalization (with comments)" << endl;
    }
    else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIC14N11_NOC)) {
        cout << "c14n 1.1 canonicalization (without comments)" << endl;
    }
    else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIC14N11_COM)) {
        cout << "c14n 1.1 canonicalization (with comments)" << endl;
    }
    else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIEXC_C14N_NOC)) {
        cout << "Exclusive c14n 1.0 canonicalization (without comments)" << endl;
    }
    else if (XMLString::equals(cm, DSIGConstants::s_unicodeStrURIEXC_C14N_COM)) {
        cout << "Exclusive c14n 1.0 canonicalization (with comments)" << endl;
    }
    else {
        cout << "Unknown c14n method" << endl;
    }

	cout << endl;

    cout << "    Signature Algorithm : ";
    char* alg = XMLString::transcode(sig->getAlgorithmURI());
    cout << (alg ? alg : "Unknown") << endl;
    XSEC_RELEASE_XMLCH(alg);

	// Read in the references and output

	if (skipReferences == false) {

		DSIGReferenceList * rl = sig->getReferenceList();
	
		if (rl != NULL) {

			cout << endl << "Reference List : " << endl;
			outputReferences(rl, 1);
	
		}
	}
}

void printUsage() {

	cerr << "\nUsage: siginf [options] <input file name>\n\n";
	cerr << "     Where options are :\n\n";
	cerr << "     --skiprefs/-s\n";
	cerr << "         Skip information on references - output main sig info only\n\n";

}

int evaluate(int argc, char ** argv) {
	
	char					* filename = NULL;
	bool					skipRefs = false;

	if (argc < 2) {

		printUsage();
		return 2;
	}

	// Run through parameters
	int paramCount = 1;

	while (paramCount < argc - 1) {

		if (_stricmp(argv[paramCount], "--skiprefs") == 0 || _stricmp(argv[paramCount], "-s") == 0) {
			skipRefs = true;
			paramCount++;
		}
		else {
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
    }

    catch (const XMLException& e)
    {
		char * msg = XMLString::transcode(e.getMessage());
        cerr << "An error occurred during parsing\n   Message: "
             << msg << endl;
		XSEC_RELEASE_XMLCH(msg);
        errorsOccured = true;
    }


    catch (const DOMException& e)
    {
       cerr << "A DOM error occurred during parsing\n   DOMException code: "
             << e.code << endl;
        errorsOccured = true;
    }

	if (errorCount > 0 || errorsOccured) {

		cout << "Errors during parse" << endl;
		return (2);

	}

	/*

		Now that we have the parsed file, get the DOM document and start looking at it

	*/
	
	DOMNode *doc = parser->getDocument();
	DOMDocument *theDOM = parser->getDocument();

	// Find the signature node
	
	DOMNode *sigNode = findDSIGNode(doc, "Signature");

	// Create the signature checker

	if (sigNode == 0) {

		cerr << "Could not find <Signature> node in " << argv[argc-1] << endl;
		return 1;
	}

	XSECProvider prov;
	DSIGSignature * sig = prov.newSignatureFromDOM(theDOM, sigNode);

	try {

		sig->load();

		// If we didn't get an exception, things went well

		cout << "Filename : " << filename << endl;

		outputSignatureInfo(sig, skipRefs);
//		if (skipRefs == false)
//			result = sig->verifySignatureOnly();
//		else
//			result = sig->verify();
	}

	catch (const XSECException &e) {
		char * msg = XMLString::transcode(e.getMsg());
		cerr << "An error occurred during signature loading\n   Message: "
		<< msg << endl;
		XSEC_RELEASE_XMLCH(msg);
		errorsOccured = true;
		return 2;
	}
	catch (...) {

		cerr << "Unknown Exception type occurred.  Cleaning up and exiting\n" << endl;
		return 2;

	}

	// Clean up

	prov.releaseSignature(sig);
	// Janitor will clean up the parser
	return 0;
}


int main(int argc, char **argv) {

	int retResult;

	/* We output a version number to overcome a "feature" in Microsoft's memory
	   leak detection */

	cout << "DSIG Info (Using Apache XML-Security-C Library v" << XSEC_VERSION_MAJOR <<
		"." << XSEC_VERSION_MEDIUM << "." << XSEC_VERSION_MINOR << ")\n";

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

	if ( _CrtMemDifference( &s3, &s1, &s2 ) && s3.lCounts[1] > 1) {

		std::cerr << "Total count = " << (unsigned int) s3.lTotalCount << endl;

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
