/*
 * Copyright 2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * imitations under the License.
 */

/*
 * XSEC
 *
 * XSECSOAPRequestorSimple := (Very) Basic implementation of a SOAP
 *                         HTTP wrapper for testing the client code.
 *
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include <xsec/utils/XSECSOAPRequestorSimple.hpp>
#include <xsec/framework/XSECError.hpp>

#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLNetAccessor.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLExceptMsgs.hpp>
#include <xercesc/util/Janitor.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

XERCES_CPP_NAMESPACE_USE

// --------------------------------------------------------------------------------
//           Platform specific constructor
// --------------------------------------------------------------------------------


XSECSOAPRequestorSimple::XSECSOAPRequestorSimple(const XMLCh * uri) : m_uri(uri) {


}

// --------------------------------------------------------------------------------
//           Interface
// --------------------------------------------------------------------------------


DOMDocument * XSECSOAPRequestorSimple::doRequest(DOMDocument * request) {


	char * content = wrapAndSerialise(request);

	// First we need to serialise

    char                fBuffer[4000];
    char *              fBufferEnd;
    char *              fBufferPos;

    //
    // Pull all of the parts of the URL out of th m_uri object, and transcode them
    //   and transcode them back to ASCII.
    //
    const XMLCh*        hostName = m_uri.getHost();
    char*               hostNameAsCharStar = XMLString::transcode(hostName);
    ArrayJanitor<char>  janBuf1(hostNameAsCharStar);

    const XMLCh*        path = m_uri.getPath();
    char*               pathAsCharStar = XMLString::transcode(path);
    ArrayJanitor<char>  janBuf2(pathAsCharStar);

    const XMLCh*        fragment = m_uri.getFragment();
    char*               fragmentAsCharStar = 0;
    if (fragment)
        fragmentAsCharStar = XMLString::transcode(fragment);
    ArrayJanitor<char>  janBuf3(fragmentAsCharStar);

    const XMLCh*        query = m_uri.getQueryString();
    char*               queryAsCharStar = 0;
    if (query)
        queryAsCharStar = XMLString::transcode(query);
    ArrayJanitor<char>  janBuf4(queryAsCharStar);		

    unsigned short      portNumber = (unsigned short) m_uri.getPort();

	// If no number is set, go with port 80
	if (portNumber == USHRT_MAX)
		portNumber = 80;

    //
    // Set up a socket.
    //
    struct hostent*     hostEntPtr = 0;
    struct sockaddr_in  sa;


    if ((hostEntPtr = gethostbyname(hostNameAsCharStar)) == NULL)
    {
        unsigned long  numAddress = inet_addr(hostNameAsCharStar);
        if (numAddress == 0)
        {
            ThrowXML(NetAccessorException,
                     XMLExcepts::NetAcc_TargetResolution);
        }
        if ((hostEntPtr =
                gethostbyaddr((char *) &numAddress,
                              sizeof(unsigned long), AF_INET)) == NULL)
        {
            ThrowXML(NetAccessorException,
                     XMLExcepts::NetAcc_TargetResolution);
        }
    }

    memcpy((void *) &sa.sin_addr,
           (const void *) hostEntPtr->h_addr, hostEntPtr->h_length);
    sa.sin_family = hostEntPtr->h_addrtype;
    sa.sin_port = htons(portNumber);

    int s = socket(hostEntPtr->h_addrtype, SOCK_STREAM, 0);
    if (s < 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
							"Error creating socket");

    }

    if (connect(s, (struct sockaddr *) &sa, sizeof(sa)) < 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
							"Error connecting to end server");
    }

    // The port is open and ready to go.
    // Build up the http GET command to send to the server.
    // To do:  We should really support http 1.1.  This implementation
    //         is weak.

    memset(fBuffer, 0, sizeof(fBuffer));

    strcpy(fBuffer, "POST ");
    strcat(fBuffer, pathAsCharStar);

    if (queryAsCharStar != 0)
    {
        // Tack on a ? before the fragment
        strcat(fBuffer,"?");
        strcat(fBuffer, queryAsCharStar);
    }

    if (fragmentAsCharStar != 0)
    {
        strcat(fBuffer, fragmentAsCharStar);
    }
    strcat(fBuffer, " HTTP/1.0\r\n");

	strcat(fBuffer, "Content-Type: text/xml; charset=utf-8\r\n");


    strcat(fBuffer, "Host: ");
    strcat(fBuffer, hostNameAsCharStar);
    if (portNumber != 80)
    {
        int i = strlen(fBuffer);
		sprintf(fBuffer+i, ":%d", portNumber);
    }
	strcat(fBuffer, "\r\n");

	strcat(fBuffer, "Content-Length: ");
    int i = (int) strlen(fBuffer);
	sprintf(fBuffer+i, "%d", strlen(content));
	strcat(fBuffer, "\r\n");
	strcat(fBuffer, "SOAPAction: \"\"\r\n");

/*	strcat(fBuffer, "Connection: Close\r\n");
	strcat(fBuffer, "Cache-Control: no-cache\r\n");*/
    strcat(fBuffer, "\r\n");

	// Now the content
	strcat(fBuffer, content);

    // Send the http request
    int lent = strlen(fBuffer);
    int  aLent = 0;
    if ((aLent = write(s, (void *) fBuffer, lent)) != lent)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
							"Error writing to socket");
    }

    //
    // get the response, check the http header for errors from the server.
    //
    aLent = read(s, (void *)fBuffer, sizeof(fBuffer)-1);
	/***/
	fBuffer[aLent] = '\0';
	printf(fBuffer);
	/***/
    if (aLent <= 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
							"Error reported reading socket");
    }

    fBufferEnd = fBuffer+aLent;
    *fBufferEnd = 0;

    // Find the break between the returned http header and any data.
    //  (Delimited by a blank line)
    // Hang on to any data for use by the first read from this BinHTTPURLInputStream.
    //
    fBufferPos = strstr(fBuffer, "\r\n\r\n");
    if (fBufferPos != 0)
    {
        fBufferPos += 4;
        *(fBufferPos-2) = 0;
    }
    else
    {
        fBufferPos = strstr(fBuffer, "\n\n");
        if (fBufferPos != 0)
        {
            fBufferPos += 2;
            *(fBufferPos-1) = 0;
        }
        else
            fBufferPos = fBufferEnd;
    }

    // Make sure the header includes an HTTP 200 OK response.
    //
    char *p = strstr(fBuffer, "HTTP");
    if (p == 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
							"Error reported reading socket");
    }

    p = strchr(p, ' ');
    if (p == 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
							"Error reported reading socket");
    }

    int httpResponse = atoi(p);

	if (httpResponse == 302 || httpResponse == 301) {
		//Once grows, should use a switch
		char redirectBuf[256];
		int q;

		// Find the "Location:" string
		p = strstr(p, "Location:");
		if (p == 0)
        {
			throw XSECException(XSECException::HTTPURIInputStreamError,
							"Error reported reading socket");
		}
		p = strchr(p, ' ');
		if (p == 0)
		{
			throw XSECException(XSECException::HTTPURIInputStreamError,
							"Error reported reading socket");
		}

		// Now read 
		p++;
		for (q=0; q < 255 && p[q] != '\r' && p[q] !='\n'; ++q)
			redirectBuf[q] = p[q];

		redirectBuf[q] = '\0';
		
		// Try to find this location
		m_uri = XMLUri(XMLString::transcode(redirectBuf));

		return doRequest(request);


	}

    else if (httpResponse != 200)
    {
        // Most likely a 404 Not Found error.
        //   Should recognize and handle the forwarding responses.
        //
		throw XSECException(XSECException::HTTPURIInputStreamError,
						"Unknown HTTP Response");
    }
	while (aLent != 0) {
		aLent = read(s, (void *)fBuffer, sizeof(fBuffer)-1);
		/***/
		fBuffer[aLent] = '\0';
		printf(fBuffer);
		/***/
	}
	return NULL;
}


