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
 * XSECDefs := File for general XSEC definitions
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

// Use Xerces to do the "hard work in determining compilers etc." for us

#ifndef XSECDEFS_HEADER
#define XSECDEFS_HEADER

// General includes

#include <assert.h>
#include <stdlib.h>

// Include the generated include file

#if defined (_WIN32)
#	include <xsec/framework/XSECW32Config.hpp>
#	if defined (_DEBUG) && defined (_XSEC_DO_MEMDEBUG)
#		define _CRTDBG_MAP_ALLOC
#		include <crtdbg.h>
#	endif
#	define WIN32_LEAN_AND_MEAN
#	include <windows.h>
#elif defined(XSEC_BUILDING_LIBRARY) || defined(XSEC_BUILDING_TOOLS)
#   include "config.h"
#else
#	include <xsec/framework/XSECConfig.hpp>
#endif

// Xalan

//#include <Include/PlatformDefinitions.hpp>

// Xerces

#include <xercesc/util/XercesDefs.hpp>

// Pending API change, compile in a limit for Xerces SecurityManager entity expansion
#define XSEC_ENTITY_EXPANSION_LIMIT 1000


// --------------------------------------------------------------------------------
//           Namespace Handling
// --------------------------------------------------------------------------------

// Use an approach similar to that used in Xalan to process Xerces namespaces

#if defined(XERCES_HAS_CPP_NAMESPACE)
#	define XSEC_USING_XERCES(NAME) using XERCES_CPP_NAMESPACE :: NAME
#	define XSEC_DECLARE_XERCES_CLASS(NAME) namespace XERCES_CPP_NAMESPACE { class NAME; }
#	define XSEC_DECLARE_XERCES_STRUCT(NAME) namespace XERCES_CPP_NAMESPACE { struct NAME; }
#else
#	define XERCES_CPP_NAMESPACE_QUALIFIER
#	define XERCES_CPP_NAMESPACE_BEGIN
#	define XERCES_CPP_NAMESPACE_END
#	define XERCES_CPP_NAMESPACE_USE
#	define XSEC_USING_XERCES(NAME)
#	define XSEC_DECLARE_XERCES_CLASS(NAME) class NAME;
#	define XSEC_DECLARE_XERCES_STRUCT(NAME) struct NAME;
#endif

#define XSEC_RELEASE_XMLCH(x) XMLString::release(&(x))

// --------------------------------------------------------------------------------
//           Project Library Handling
// --------------------------------------------------------------------------------

#if defined(DLL_EXPORT)
  #if defined(XSEC_BUILDING_LIBRARY)
    #define XSEC_EXPORT XERCES_PLATFORM_EXPORT
  #else
    #define XSEC_EXPORT XERCES_PLATFORM_IMPORT
  #endif
#else
  #define XSEC_EXPORT
#endif


// Platform includes.  Much of this is taken from Xalan

#if defined(_MSC_VER)

// Microsoft VC++

#	pragma warning(disable: 4127 4251 4511 4503 4512 4514 4702 4710 4711 4786 4097; error: 4150 4172 4238 4239 4715)
#	define XSEC_NO_COVARIANT_RETURN_TYPE
/*
 * Removed to allow any compiler to compile - might not work, but ....
 * #elif defined(__GNUC__)
 * #elif defined(__INTEL_COMPILER)
 * #else
 * #error Unknown compiler.
 */
#endif


// Configuration includes

#if defined(XSEC_BUILDING_LIBRARY) || defined(XSEC_BUILDING_TOOLS)
#   ifdef HAVE_STRCASECMP
#       define _stricmp(x,y) strcasecmp(x,y)
#   else
#       define _stricmp(x,y) stricmp(x,y)
#   endif
#endif

#endif /* XSECDEFS_HEADER */
