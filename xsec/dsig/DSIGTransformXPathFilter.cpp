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
 * DSIGTransformXPathFilter := Class that performs XPath Filter 
 *                             transforms
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#include <xsec/dsig/DSIGSignature.hpp>
#include <xsec/dsig/DSIGTransformXPathFilter.hpp>
#include <xsec/dsig/DSIGXPathFilterExpr.hpp>
#include <xsec/framework/XSECEnv.hpp>
#include <xsec/framework/XSECError.hpp>
#include <xsec/transformers/TXFMChain.hpp>

#include "../utils/XSECDOMUtils.hpp"

#include <xercesc/dom/DOMNode.hpp>

XERCES_CPP_NAMESPACE_USE

// --------------------------------------------------------------------------------
//           Construct/Destruct
// --------------------------------------------------------------------------------

DSIGTransformXPathFilter::DSIGTransformXPathFilter(const XSECEnv * env, DOMNode * node) :
DSIGTransform(env, node),
m_loaded(false) {

}


DSIGTransformXPathFilter::DSIGTransformXPathFilter(const XSECEnv * env) :
DSIGTransform(env),
m_loaded(false) {

}


DSIGTransformXPathFilter::~DSIGTransformXPathFilter() {

    for (exprVectorType::iterator i = m_exprs.begin(); i != m_exprs.end(); ++i) {
        delete (*i);
    }
}


void DSIGTransformXPathFilter::appendTransformer(TXFMChain * input) {

    if (m_loaded == false) {
        throw XSECException(XSECException::XPathFilterError,
            "DSIGTransformXPathFilter::appendTransform - load not yet called");
    }

    throw XSECException(XSECException::UnsupportedFunction,
        "XPath transforms are not supported in this build of the XSEC library");
}

// --------------------------------------------------------------------------------
//           Create a blank transform
// --------------------------------------------------------------------------------


DOMElement * DSIGTransformXPathFilter::createBlankTransform(DOMDocument* parentDoc) {

    safeBuffer str;
    const XMLCh * prefix;
    DOMElement *ret;
    DOMDocument *doc = mp_env->getParentDocument();

    prefix = mp_env->getDSIGNSPrefix();

    // Create the transform node
    makeQName(str, prefix, "Transform");
    ret = doc->createElementNS(DSIGConstants::s_unicodeStrURIDSIG, str.rawXMLChBuffer());
    ret->setAttributeNS(NULL,DSIGConstants::s_unicodeStrAlgorithm, DSIGConstants::s_unicodeStrURIXPF);

    mp_txfmNode = ret;

    m_loaded = true;

    return ret;
}

DSIGXPathFilterExpr* DSIGTransformXPathFilter::appendFilter(
        DSIGXPathFilterExpr::XPathFilterType filterType,
        const XMLCh* filterExpr) {

    DSIGXPathFilterExpr * e;

    XSECnew(e, DSIGXPathFilterExpr(mp_env));

    DOMNode * elt = e->setFilter(filterType, filterExpr);
    m_exprs.push_back(e);

    mp_txfmNode->appendChild(elt);
    mp_env->doPrettyPrint(mp_txfmNode);

    return e;

}

// --------------------------------------------------------------------------------
//           Load from XML
// --------------------------------------------------------------------------------

void DSIGTransformXPathFilter::load() {

    if (mp_txfmNode == NULL) {
        throw XSECException(XSECException::XPathFilterError,
            "DSIGTransformXPathFilter::load called on NULL node");
    }

    // Very simple - go through each child.  If it's an XPath child
    // Create the DSIGXPathFilterExpr object

    DOMNode * n = mp_txfmNode->getFirstChild();

    while (n != NULL) {
        if (n->getNodeType() == DOMNode::ELEMENT_NODE &&
            strEquals(getXPFLocalName(n), "XPath")) {

            DSIGXPathFilterExpr * xpf;
            XSECnew(xpf, DSIGXPathFilterExpr(mp_env, n));

            // Add it to the vector prior to load to ensure deleted if
            // anything throws an exception

            m_exprs.push_back(xpf);

            xpf->load();
        }

        n = n->getNextSibling();
    }

    m_loaded = true;
}

// --------------------------------------------------------------------------------
//           Retrieve expression information
// --------------------------------------------------------------------------------

unsigned int DSIGTransformXPathFilter::getExprNum() const {
    return (unsigned int) m_exprs.size();
}


DSIGXPathFilterExpr* DSIGTransformXPathFilter::expr(unsigned int n) const {

    if (n < m_exprs.size())
        return m_exprs[n];

    return NULL;
}
