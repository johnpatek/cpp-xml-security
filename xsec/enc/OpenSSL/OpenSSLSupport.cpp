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

#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <xsec/enc/OpenSSL/OpenSSLSupport.hpp>

const BIGNUM *DSA_get0_pubkey(const DSA *dsa)
{
    const BIGNUM *result;
    DSA_get0_key(dsa, &result, NULL);
    return result;
}

const BIGNUM *DSA_get0_privkey(const DSA *dsa)
{
    const BIGNUM *result;
    DSA_get0_key(dsa, NULL, &result);
    return result;
}

EvpEncodeCtxRAII::EvpEncodeCtxRAII() : mp_ctx(EVP_ENCODE_CTX_new()) { };
EvpEncodeCtxRAII::~EvpEncodeCtxRAII() {
    if (mp_ctx) 
        EVP_ENCODE_CTX_free(mp_ctx);
}

EVP_ENCODE_CTX
*EvpEncodeCtxRAII::of()  {
    return mp_ctx;
}

#endif
