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
#if !defined(XSEC_OPENSSL_SUPPORT_H)
#define XSEC_OPENSSL_SUPPORT_H 1

#if defined (XSEC_HAVE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#if defined (XSEC_OPENSSL_HAVE_EC)
#include <openssl/ecdsa.h>
#endif

// Our own helper functions
const BIGNUM *DSA_get0_pubkey(const DSA *dsa);
const BIGNUM *DSA_get0_privkey(const DSA *dsa);

#define DUP_NON_NULL(_what_) ((_what_)?BN_dup((_what_)):NULL)

/**
 * \brief RAII for EVP_ENCODE_CTX
 *
 * In OpenSSL 1.1 EVP_ENCODE_CTX becomes opaque so we cannot
 * just create one on the stack
 */

class EvpEncodeCtxRAII
{
public:
    EvpEncodeCtxRAII();

    ~EvpEncodeCtxRAII();

    EVP_ENCODE_CTX *of(void);

private:
    EVP_ENCODE_CTX *mp_ctx;
};


#endif
#endif
