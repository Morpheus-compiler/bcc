/*
 * Copyright (c) 2008, 2009, 2010, 2012 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "jhash.h"

#include <cstdint>
#include <cstddef>
#include <arpa/inet.h>

/* This is the public domain lookup3 hash by Bob Jenkins from
 * http://burtleburtle.net/bob/c/lookup3.c, modified for style. */

#define JHASH_INITVAL    0xdeadbeef

//static inline uint32_t
//jhash_rot(uint32_t x, int k)
//{
//  return (x << k) | (x >> (32 - k));
//}

static inline uint32_t jhash_rot(uint32_t word, unsigned int shift) {
  return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

//static inline void
//jhash_mix(uint32_t *a, uint32_t *b, uint32_t *c)
//{
//  *a -= *c; *a ^= jhash_rot(*c,  4); *c += *b;
//  *b -= *a; *b ^= jhash_rot(*a,  6); *a += *c;
//  *c -= *b; *c ^= jhash_rot(*b,  8); *b += *a;
//  *a -= *c; *a ^= jhash_rot(*c, 16); *c += *b;
//  *b -= *a; *b ^= jhash_rot(*a, 19); *a += *c;
//  *c -= *b; *c ^= jhash_rot(*b,  4); *b += *a;
//}

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define jhash_mix(a, b, c)      \
{            \
  a -= c;  a ^= jhash_rot(c, 4);  c += b;  \
  b -= a;  b ^= jhash_rot(a, 6);  a += c;  \
  c -= b;  c ^= jhash_rot(b, 8);  b += a;  \
  a -= c;  a ^= jhash_rot(c, 16); c += b;  \
  b -= a;  b ^= jhash_rot(a, 19); a += c;  \
  c -= b;  c ^= jhash_rot(b, 4);  b += a;  \
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define jhash_final(a, b, c)      \
{            \
  c ^= b; c -= jhash_rot(b, 14);    \
  a ^= c; a -= jhash_rot(c, 11);    \
  b ^= a; b -= jhash_rot(a, 25);    \
  c ^= b; c -= jhash_rot(b, 16);    \
  a ^= c; a -= jhash_rot(c, 4);    \
  b ^= a; b -= jhash_rot(a, 14);    \
  c ^= b; c -= jhash_rot(b, 24);    \
}

//static inline void
//jhash_final(uint32_t *a, uint32_t *b, uint32_t *c)
//{
//  *c ^= *b; *c -= jhash_rot(*b, 14);
//  *a ^= *c; *a -= jhash_rot(*c, 11);
//  *b ^= *a; *b -= jhash_rot(*a, 25);
//  *c ^= *b; *c -= jhash_rot(*b, 16);
//  *a ^= *c; *a -= jhash_rot(*c,  4);
//  *b ^= *a; *b -= jhash_rot(*a, 14);
//  *c ^= *b; *c -= jhash_rot(*b, 24);
//}

/* Returns the Jenkins hash of the 'n' 32-bit words at 'p', starting from
 * 'basis'.  'p' must be properly aligned.
 *
 * Use hash_words() instead, unless you're computing a hash function whose
 * value is exposed "on the wire" so we don't want to change it. */
uint32_t
jhash_words(const uint32_t *k, uint32_t length, uint32_t initval) {
  uint32_t a, b, c;

  /* Set up the internal state */
  a = b = c = JHASH_INITVAL + (length << 2) + initval;

  /* Handle most of the key */
  while (length > 3) {
    a += k[0];
    b += k[1];
    c += k[2];
    jhash_mix(a, b, c);
    length -= 3;
    k += 3;
  }

  /* Handle the last 3 u32's */
  switch (length) {
    case 3:
      c += k[2];  /* fall through */
    case 2:
      b += k[1];  /* fall through */
    case 1:
      a += k[0];
      jhash_final(a, b, c);
    case 0:  /* Nothing left to add */
      break;
  }

  return c;
}

struct __una_u32 {
    uint32_t x __attribute__((packed));
};

static inline uint32_t get_unaligned_u32(const void *p) {
  const struct __una_u32 *ptr = (const struct __una_u32 *) p;
  return ptr->x;
}

/* Returns the Jenkins hash of the 'n' bytes at 'p', starting from 'basis'.
 *
 * Use hash_bytes() instead, unless you're computing a hash function whose
 * value is exposed "on the wire" so we don't want to change it. */
uint32_t
jhash_bytes(const void *p_, uint32_t length, uint32_t initval) {
//  const auto *p = static_cast<const uint32_t *>(p_);
  const auto *k = static_cast<const uint8_t *>(p_);
  uint32_t a, b, c;

  a = b = c = JHASH_INITVAL + length + initval;

  while (length > 12) {
    a += get_unaligned_u32(k);
    b += get_unaligned_u32(k + 4);
    c += get_unaligned_u32(k + 8);
    jhash_mix(a, b, c);
    length -= 12;
    k += 12;
  }

  /* Last block: affect all 32 bits of (c) */
  switch (length) {
    case 12:
      c += (uint32_t) k[11] << 24;  /* fall through */
    case 11:
      c += (uint32_t) k[10] << 16;  /* fall through */
    case 10:
      c += (uint32_t) k[9] << 8;  /* fall through */
    case 9:
      c += k[8];    /* fall through */
    case 8:
      b += (uint32_t) k[7] << 24;  /* fall through */
    case 7:
      b += (uint32_t) k[6] << 16;  /* fall through */
    case 6:
      b += (uint32_t) k[5] << 8;  /* fall through */
    case 5:
      b += k[4];    /* fall through */
    case 4:
      a += (uint32_t) k[3] << 24;  /* fall through */
    case 3:
      a += (uint32_t) k[2] << 16;  /* fall through */
    case 2:
      a += (uint32_t) k[1] << 8;  /* fall through */
    case 1:
      a += k[0];
      jhash_final(a, b, c);
    case 0: /* Nothing left to add */
      break;
  }

  return c;
}