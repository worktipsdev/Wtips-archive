// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <stddef.h>
#include <iostream>

#include "generic-ops.h"
#include "hex.h"
#include "span.h"
#include "crypto/cn_heavy_hash.hpp"
#include "argon2.h"

namespace crypto {

  extern "C" {
#include "hash-ops.h"
  }

    static bool argon2_optimization_selected = false;

  struct alignas(size_t) hash {
    char data[HASH_SIZE];
  };
  struct hash8 {
    char data[8];
  };

  static_assert(sizeof(hash) == HASH_SIZE, "Invalid structure size");
  static_assert(sizeof(hash8) == 8, "Invalid structure size");

  /*
    Cryptonight hash functions
  */

  inline void cn_fast_hash(const void *data, std::size_t length, hash &hash) {
    cn_fast_hash(data, length, reinterpret_cast<char *>(&hash));
  }

  inline hash cn_fast_hash(const void *data, std::size_t length) {
    hash h;
    cn_fast_hash(data, length, reinterpret_cast<char *>(&h));
    return h;
  }

  enum struct cn_slow_hash_type
  {
    heavy_v1,
    heavy_v2,
    turtle_lite_v2,
	chukwa_slow_hash,
  };

  inline void cn_slow_hash(const void *data, std::size_t length, hash &hash, cn_slow_hash_type type) {
    switch(type)
    {
      case cn_slow_hash_type::heavy_v1:
      case cn_slow_hash_type::heavy_v2:
      {
        static thread_local cn_heavy_hash_v2 v2;
        static thread_local cn_heavy_hash_v1 v1 = cn_heavy_hash_v1::make_borrowed(v2);

        if (type == cn_slow_hash_type::heavy_v1) v1.hash(data, length, hash.data);
        else                                     v2.hash(data, length, hash.data);
      }
      break;

      case cn_slow_hash_type::turtle_lite_v2:
      {
         const uint32_t CN_TURTLE_SCRATCHPAD = 262144;
         const uint32_t CN_TURTLE_ITERATIONS = 131072;
         cn_turtle_hash(data,
             length,
             hash.data,
             1, // light
             2, // variant
             0, // pre-hashed
             CN_TURTLE_SCRATCHPAD, CN_TURTLE_ITERATIONS);
      }
      break;
	    case cn_slow_hash_type::chukwa_slow_hash:
      default:
      {
		 // Chukwa Common Definitions
         const uint32_t CHUKWA_HASHLEN = 32; // The length of the resulting hash in bytes
         const uint32_t CHUKWA_SALTLEN = 16; // The length of our salt in bytes
		 
		 // Chukwa v2 Definitions
         const uint32_t CHUKWA_THREADS = 1; // How many threads to use at once
         const uint32_t CHUKWA_ITERS = 4; // How many iterations we perform as part of our slow-hash
         const uint32_t CHUKWA_MEMORY = 1024; // This value is in KiB (1.00MB)		 

		 uint8_t salt[CHUKWA_SALTLEN];
        memcpy(salt, data, sizeof(salt));

        /* If this is the first time we've called this hash function then
           we need to have the Argon2 library check to see if any of the
           available CPU instruction sets are going to help us out */
        if (!argon2_optimization_selected)
        {
            /* Call the library quick benchmark test to set which CPU
               instruction sets will be used */
            argon2_select_impl(NULL, NULL);

            argon2_optimization_selected = true;
        }

        argon2id_hash_raw(
            CHUKWA_ITERS, CHUKWA_MEMORY, CHUKWA_THREADS, data, length, salt, CHUKWA_SALTLEN, hash.data, CHUKWA_HASHLEN);

      }
      break;
    }
  }

  inline void tree_hash(const hash *hashes, std::size_t count, hash &root_hash) {
    tree_hash(reinterpret_cast<const char (*)[HASH_SIZE]>(hashes), count, reinterpret_cast<char *>(&root_hash));
  }

  inline std::ostream &operator <<(std::ostream &o, const crypto::hash &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }
  inline std::ostream &operator <<(std::ostream &o, const crypto::hash8 &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }

  const static crypto::hash null_hash = {};
  const static crypto::hash8 null_hash8 = {};
}

EPEE_TYPE_IS_SPANNABLE(crypto::hash)
CRYPTO_MAKE_HASHABLE(hash)
CRYPTO_MAKE_COMPARABLE(hash8)
