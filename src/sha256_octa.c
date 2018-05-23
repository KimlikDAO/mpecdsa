/// octa-instance sha-256 evaluation on 1 block
/// the hard-wired padding routines assume that the data is exactly 48 bytes
/// so that sha-256 only requires 1 iteration of the compression loop.
///
/// aas 2017
///

#include <immintrin.h>
#include <memory.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>


static unsigned long _H[] __attribute__ ((aligned (64))) = {
	0x6a09e6676a09e667, 0x6a09e6676a09e667, 0x6a09e6676a09e667, 0x6a09e6676a09e667, 
	0xbb67ae85bb67ae85, 0xbb67ae85bb67ae85, 0xbb67ae85bb67ae85, 0xbb67ae85bb67ae85, 
	0x3c6ef3723c6ef372, 0x3c6ef3723c6ef372, 0x3c6ef3723c6ef372, 0x3c6ef3723c6ef372, 
	0xa54ff53aa54ff53a, 0xa54ff53aa54ff53a, 0xa54ff53aa54ff53a, 0xa54ff53aa54ff53a, 
	0x510e527f510e527f, 0x510e527f510e527f, 0x510e527f510e527f, 0x510e527f510e527f, 
	0x9b05688c9b05688c, 0x9b05688c9b05688c, 0x9b05688c9b05688c, 0x9b05688c9b05688c, 
	0x1f83d9ab1f83d9ab, 0x1f83d9ab1f83d9ab, 0x1f83d9ab1f83d9ab, 0x1f83d9ab1f83d9ab, 
	0x5be0cd195be0cd19, 0x5be0cd195be0cd19, 0x5be0cd195be0cd19, 0x5be0cd195be0cd19, 
};

// padding for 52-byte inputs
static unsigned long _P[] __attribute__ ((aligned (64))) = {
	0x8000000080000000, 0x8000000080000000, 0x8000000080000000, 0x8000000080000000, 
	0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 
	0x000001A0000001A0, 0x000001A0000001A0, 0x000001A0000001A0, 0x000001A0000001A0, 
};

// SHA256 constants, repeated to fill vector
static unsigned long _K[] __attribute__ ((aligned (64))) = {
	0x428a2f98428a2f98, 0x428a2f98428a2f98,
	0x428a2f98428a2f98, 0x428a2f98428a2f98,
	0x7137449171374491, 0x7137449171374491,
	0x7137449171374491, 0x7137449171374491,
	0xb5c0fbcfb5c0fbcf, 0xb5c0fbcfb5c0fbcf,
	0xb5c0fbcfb5c0fbcf, 0xb5c0fbcfb5c0fbcf,
	0xe9b5dba5e9b5dba5, 0xe9b5dba5e9b5dba5,
	0xe9b5dba5e9b5dba5, 0xe9b5dba5e9b5dba5,
	0x3956c25b3956c25b, 0x3956c25b3956c25b,
	0x3956c25b3956c25b, 0x3956c25b3956c25b,
	0x59f111f159f111f1, 0x59f111f159f111f1,
	0x59f111f159f111f1, 0x59f111f159f111f1,
	0x923f82a4923f82a4, 0x923f82a4923f82a4,
	0x923f82a4923f82a4, 0x923f82a4923f82a4,
	0xab1c5ed5ab1c5ed5, 0xab1c5ed5ab1c5ed5,
	0xab1c5ed5ab1c5ed5, 0xab1c5ed5ab1c5ed5,
	0xd807aa98d807aa98, 0xd807aa98d807aa98,
	0xd807aa98d807aa98, 0xd807aa98d807aa98,
	0x12835b0112835b01, 0x12835b0112835b01,
	0x12835b0112835b01, 0x12835b0112835b01,
	0x243185be243185be, 0x243185be243185be,
	0x243185be243185be, 0x243185be243185be,
	0x550c7dc3550c7dc3, 0x550c7dc3550c7dc3,
	0x550c7dc3550c7dc3, 0x550c7dc3550c7dc3,
	0x72be5d7472be5d74, 0x72be5d7472be5d74,
	0x72be5d7472be5d74, 0x72be5d7472be5d74,
	0x80deb1fe80deb1fe, 0x80deb1fe80deb1fe,
	0x80deb1fe80deb1fe, 0x80deb1fe80deb1fe,
	0x9bdc06a79bdc06a7, 0x9bdc06a79bdc06a7,
	0x9bdc06a79bdc06a7, 0x9bdc06a79bdc06a7,
	0xc19bf174c19bf174, 0xc19bf174c19bf174,
	0xc19bf174c19bf174, 0xc19bf174c19bf174,
	0xe49b69c1e49b69c1, 0xe49b69c1e49b69c1,
	0xe49b69c1e49b69c1, 0xe49b69c1e49b69c1,
	0xefbe4786efbe4786, 0xefbe4786efbe4786,
	0xefbe4786efbe4786, 0xefbe4786efbe4786,
	0x0fc19dc60fc19dc6, 0x0fc19dc60fc19dc6,
	0x0fc19dc60fc19dc6, 0x0fc19dc60fc19dc6,
	0x240ca1cc240ca1cc, 0x240ca1cc240ca1cc,
	0x240ca1cc240ca1cc, 0x240ca1cc240ca1cc,
	0x2de92c6f2de92c6f, 0x2de92c6f2de92c6f,
	0x2de92c6f2de92c6f, 0x2de92c6f2de92c6f,
	0x4a7484aa4a7484aa, 0x4a7484aa4a7484aa,
	0x4a7484aa4a7484aa, 0x4a7484aa4a7484aa,
	0x5cb0a9dc5cb0a9dc, 0x5cb0a9dc5cb0a9dc,
	0x5cb0a9dc5cb0a9dc, 0x5cb0a9dc5cb0a9dc,
	0x76f988da76f988da, 0x76f988da76f988da,
	0x76f988da76f988da, 0x76f988da76f988da,
	0x983e5152983e5152, 0x983e5152983e5152,
	0x983e5152983e5152, 0x983e5152983e5152,
	0xa831c66da831c66d, 0xa831c66da831c66d,
	0xa831c66da831c66d, 0xa831c66da831c66d,
	0xb00327c8b00327c8, 0xb00327c8b00327c8,
	0xb00327c8b00327c8, 0xb00327c8b00327c8,
	0xbf597fc7bf597fc7, 0xbf597fc7bf597fc7,
	0xbf597fc7bf597fc7, 0xbf597fc7bf597fc7,
	0xc6e00bf3c6e00bf3, 0xc6e00bf3c6e00bf3,
	0xc6e00bf3c6e00bf3, 0xc6e00bf3c6e00bf3,
	0xd5a79147d5a79147, 0xd5a79147d5a79147,
	0xd5a79147d5a79147, 0xd5a79147d5a79147,
	0x06ca635106ca6351, 0x06ca635106ca6351,
	0x06ca635106ca6351, 0x06ca635106ca6351,
	0x1429296714292967, 0x1429296714292967,
	0x1429296714292967, 0x1429296714292967,
	0x27b70a8527b70a85, 0x27b70a8527b70a85,
	0x27b70a8527b70a85, 0x27b70a8527b70a85,
	0x2e1b21382e1b2138, 0x2e1b21382e1b2138,
	0x2e1b21382e1b2138, 0x2e1b21382e1b2138,
	0x4d2c6dfc4d2c6dfc, 0x4d2c6dfc4d2c6dfc,
	0x4d2c6dfc4d2c6dfc, 0x4d2c6dfc4d2c6dfc,
	0x53380d1353380d13, 0x53380d1353380d13,
	0x53380d1353380d13, 0x53380d1353380d13,
	0x650a7354650a7354, 0x650a7354650a7354,
	0x650a7354650a7354, 0x650a7354650a7354,
	0x766a0abb766a0abb, 0x766a0abb766a0abb,
	0x766a0abb766a0abb, 0x766a0abb766a0abb,
	0x81c2c92e81c2c92e, 0x81c2c92e81c2c92e,
	0x81c2c92e81c2c92e, 0x81c2c92e81c2c92e,
	0x92722c8592722c85, 0x92722c8592722c85,
	0x92722c8592722c85, 0x92722c8592722c85,
	0xa2bfe8a1a2bfe8a1, 0xa2bfe8a1a2bfe8a1,
	0xa2bfe8a1a2bfe8a1, 0xa2bfe8a1a2bfe8a1,
	0xa81a664ba81a664b, 0xa81a664ba81a664b,
	0xa81a664ba81a664b, 0xa81a664ba81a664b,
	0xc24b8b70c24b8b70, 0xc24b8b70c24b8b70,
	0xc24b8b70c24b8b70, 0xc24b8b70c24b8b70,
	0xc76c51a3c76c51a3, 0xc76c51a3c76c51a3,
	0xc76c51a3c76c51a3, 0xc76c51a3c76c51a3,
	0xd192e819d192e819, 0xd192e819d192e819,
	0xd192e819d192e819, 0xd192e819d192e819,
	0xd6990624d6990624, 0xd6990624d6990624,
	0xd6990624d6990624, 0xd6990624d6990624,
	0xf40e3585f40e3585, 0xf40e3585f40e3585,
	0xf40e3585f40e3585, 0xf40e3585f40e3585,
	0x106aa070106aa070, 0x106aa070106aa070,
	0x106aa070106aa070, 0x106aa070106aa070,
	0x19a4c11619a4c116, 0x19a4c11619a4c116,
	0x19a4c11619a4c116, 0x19a4c11619a4c116,
	0x1e376c081e376c08, 0x1e376c081e376c08,
	0x1e376c081e376c08, 0x1e376c081e376c08,
	0x2748774c2748774c, 0x2748774c2748774c,
	0x2748774c2748774c, 0x2748774c2748774c,
	0x34b0bcb534b0bcb5, 0x34b0bcb534b0bcb5,
	0x34b0bcb534b0bcb5, 0x34b0bcb534b0bcb5,
	0x391c0cb3391c0cb3, 0x391c0cb3391c0cb3,
	0x391c0cb3391c0cb3, 0x391c0cb3391c0cb3,
	0x4ed8aa4a4ed8aa4a, 0x4ed8aa4a4ed8aa4a,
	0x4ed8aa4a4ed8aa4a, 0x4ed8aa4a4ed8aa4a,
	0x5b9cca4f5b9cca4f, 0x5b9cca4f5b9cca4f,
	0x5b9cca4f5b9cca4f, 0x5b9cca4f5b9cca4f,
	0x682e6ff3682e6ff3, 0x682e6ff3682e6ff3,
	0x682e6ff3682e6ff3, 0x682e6ff3682e6ff3,
	0x748f82ee748f82ee, 0x748f82ee748f82ee,
	0x748f82ee748f82ee, 0x748f82ee748f82ee,
	0x78a5636f78a5636f, 0x78a5636f78a5636f,
	0x78a5636f78a5636f, 0x78a5636f78a5636f,
	0x84c8781484c87814, 0x84c8781484c87814,
	0x84c8781484c87814, 0x84c8781484c87814,
	0x8cc702088cc70208, 0x8cc702088cc70208,
	0x8cc702088cc70208, 0x8cc702088cc70208,
	0x90befffa90befffa, 0x90befffa90befffa,
	0x90befffa90befffa, 0x90befffa90befffa,
	0xa4506ceba4506ceb, 0xa4506ceba4506ceb,
	0xa4506ceba4506ceb, 0xa4506ceba4506ceb,
	0xbef9a3f7bef9a3f7, 0xbef9a3f7bef9a3f7,
	0xbef9a3f7bef9a3f7, 0xbef9a3f7bef9a3f7,
	0xc67178f2c67178f2, 0xc67178f2c67178f2,
	0xc67178f2c67178f2, 0xc67178f2c67178f2
};


// shuffle mask for changing to big-endian
static unsigned long _pmask[] __attribute__ ((aligned (64))) = {
	0x0405060700010203, 0x0c0d0e0f08090a0b,
	0x0405060700010203, 0x0c0d0e0f08090a0b,
};




// ; TRANSPOSE8 r0, r1, r2, r3, r4, r5, r6, r7, t0, t1
// ; "transpose" data in {r0...r7} using temps {t0...t1}
// ; Input looks like: {r0 r1 r2 r3 r4 r5 r6 r7}
// ; r0 = {a7 a6 a5 a4   a3 a2 a1 a0}
// ; r1 = {b7 b6 b5 b4   b3 b2 b1 b0}
// ; r2 = {c7 c6 c5 c4   c3 c2 c1 c0}
// ; r3 = {d7 d6 d5 d4   d3 d2 d1 d0}
// ; r4 = {e7 e6 e5 e4   e3 e2 e1 e0}
// ; r5 = {f7 f6 f5 f4   f3 f2 f1 f0}
// ; r6 = {g7 g6 g5 g4   g3 g2 g1 g0}
// ; r7 = {h7 h6 h5 h4   h3 h2 h1 h0}
// ;
// ; Output looks like: {r0 r1 r2 r3 r4 r5 r6 r7}
// ; r0 = {h0 g0 f0 e0   d0 c0 b0 a0}
// ; r1 = {h1 g1 f1 e1   d1 c1 b1 a1}
// ; r2 = {h2 g2 f2 e2   d2 c2 b2 a2}
// ; r3 = {h3 g3 f3 e3   d3 c3 b3 a3}
// ; r4 = {h4 g4 f4 e4   d4 c4 b4 a4}
// ; r5 = {h5 g5 f5 e5   d5 c5 b5 a5}
// ; r6 = {h6 g6 f6 e6   d6 c6 b6 a6}
// ; r7 = {h7 g7 f7 e7   d7 c7 b7 a7}

// t0 = {b5 b4 a5 a4   b1 b0 a1 a0} \
// r0 = {b7 b6 a7 a6   b3 b2 a3 a2} \
// t1 = {d5 d4 c5 c4   d1 d0 c1 c0} \
// r2 = {d7 d6 c7 c6   d3 d2 c3 c2} \
// r3 = {d5 c5 b5 a5   d1 c1 b1 a1} \
// r1 = {d6 c6 b6 a6   d2 c2 b2 a2} \
// r0 = {d7 c7 b7 a7   d3 c3 b3 a3} \
// t0 = {d4 c4 b4 a4   d0 c0 b0 a0} \
//	r2 = {f5 f4 e5 e4   f1 f0 e1 e0} \
//	r4 = {f7 f6 e7 e6   f3 f2 e3 e2} \
//	t1 = {h5 h4 g5 g4   h1 h0 g1 g0} \
//	r6 = {h7 h6 g7 g6   h3 h2 g3 g2} \
//	r7 = {h5 g5 f5 e5   h1 g1 f1 e1} \
//	r5 = {h6 g6 f6 e6   h2 g2 f2 e2} \
//	r4 = {h7 g7 f7 e7   h3 g3 f3 e3} \
//	t1 = {h4 g4 f4 e4   h0 g0 f0 e0} \
// h6...a6 \
// h2...a2 \
// h5...a5 \
// h1...a1 \
// h7...a7 \
// h3...a3 \
// h4...a4 \
// h0...a0 \

#define TRANS8(r0,r1,r2,r3,r4,r5,r6,r7,t0,t1)  \
	t0 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r0), _mm256_castsi256_ps(r1), 0x44)); \
	r0 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r0), _mm256_castsi256_ps(r1), 0xEE)); \
	t1 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r2), _mm256_castsi256_ps(r3), 0x44)); \
	r2 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r2), _mm256_castsi256_ps(r3), 0xEE)); \
	r3 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(t0), _mm256_castsi256_ps(t1), 0xDD)); \
	r1 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r0), _mm256_castsi256_ps(r2), 0x88)); \
	r0 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r0), _mm256_castsi256_ps(r2), 0xDD)); \
	t0 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(t0), _mm256_castsi256_ps(t1), 0x88)); \
	r2 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r4), _mm256_castsi256_ps(r5), 0x44)); \
	r4 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r4), _mm256_castsi256_ps(r5), 0xEE)); \
	t1 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r6), _mm256_castsi256_ps(r7), 0x44)); \
	r6 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r6), _mm256_castsi256_ps(r7), 0xEE)); \
	r7 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r2), _mm256_castsi256_ps(t1), 0xDD)); \
	r5 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r4), _mm256_castsi256_ps(r6), 0x88)); \
	r4 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r4), _mm256_castsi256_ps(r6), 0xDD)); \
	t1 = _mm256_castps_si256(_mm256_shuffle_ps(_mm256_castsi256_ps(r2), _mm256_castsi256_ps(t1), 0x88)); \
	r6 = _mm256_permute2f128_si256 (r5, r1, 0x13); \
	r2 = _mm256_permute2f128_si256 (r5, r1, 0x02); \
	r5 = _mm256_permute2f128_si256 (r7, r3, 0x13); \
	r1 = _mm256_permute2f128_si256 (r7, r3, 0x02); \
	r7 = _mm256_permute2f128_si256 (r4, r0, 0x13); \
	r3 = _mm256_permute2f128_si256 (r4, r0, 0x02); \
	r4 = _mm256_permute2f128_si256 (t1, t0, 0x13); \
	r0 = _mm256_permute2f128_si256 (t1, t0, 0x02); \



void pp(__m256i p) {
	int *pi = (int*)&p;
	printf("%08x %08x %08x %08x %08x %08x %08x %08x\n",
//    	pi[7], pi[6], pi[5], pi[4], pi[3], pi[2], pi[1], pi[0]);
    	pi[0], pi[1], pi[2], pi[3], pi[4], pi[5], pi[6], pi[7]);
}

#define RR(out,in,s1,s2,s3) { \
	__m256i i0, i1, o;	\
	i0 = _mm256_slli_epi32(in, (32-s1));	\
	i1 = _mm256_srli_epi32(in, (s1));		\
	o  = _mm256_or_si256(i0, i1);			\
	i0 = _mm256_slli_epi32(in, (32-s2));	\
	i1 = _mm256_srli_epi32(in, (s2));		\
	i0 = _mm256_or_si256(i0, i1);			\
	o = _mm256_xor_si256(o, i0);			\
	i0 = _mm256_slli_epi32(in, (32-s3));	\
	i1 = _mm256_srli_epi32(in, (s3));		\
	i0 = _mm256_or_si256(i0, i1);			\
	out = _mm256_xor_si256(o, i0);			\
	}	\


#define ROUND(a,b,c,d,e,f,g,h,wi,i) {\
	__m256i s0, s1, maj, ch, temp1, temp2, ki, i0;\
	/*	S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25) */ \
	ki = _mm256_loadu_si256 ((__m256i const*)(_K + 4*(i)));	\
	\
	RR(s1, e, 6, 11, 25) \
	\
	/* ch := (e and f) xor ((not e) and g) = e(f^g) + g */ \
	ch = _mm256_xor_si256(f, g);	\
	ch = _mm256_and_si256(ch, e);	\
	ch = _mm256_xor_si256(ch, g);	\
	\
	/* temp1 := h + S1 + ch + k[i] + w[i]*/ \
	ki    = _mm256_add_epi32 (wi, ki);		\
	temp1 = _mm256_add_epi32 (h, s1);		\
	ki = _mm256_add_epi32 (ki, ch);			\
	temp1 = _mm256_add_epi32 (temp1, ki);	\
	\
	/* S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22) */ \
	RR( s0, a, 2, 13, 22)	\
	\
	/* maj := (a and b) xor (a and c) xor (b and c) = b*(a^c) + ac */ \
	i0  = _mm256_xor_si256(a, c);	\
	maj = _mm256_and_si256(i0, b);	\
	i0  = _mm256_and_si256(a, c);	\
	maj = _mm256_xor_si256(maj, i0);\
	\
	/* temp2 := S0 + maj */ \
 	temp2 = _mm256_add_epi32 (s0, maj); \
 	\
 	h = g;	\
 	g = f;	\
 	f = e;	\
 	e = _mm256_add_epi32 (d, temp1);	/*  e := d + temp1 */ \
 	d = c;	\
 	c = b;	\
 	b = a;	\
 	a = _mm256_add_epi32 (temp1, temp2);/*  a := temp1 + temp2 */ \
	}

// 16 15 7 2
//  s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
//  s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
//  w[i] := w[i-16] + s0 + w[i-7] + s1

#define KEY(w_16, w_0, w_1, w_9, w_14) \
	__m256i w_16 = _mm256_add_epi32(w_0, w_9); { \
	__m256i s0, i0, i1, o;				\
	/* 	 7, 18, 3 operation	*/ \
	i0 = _mm256_slli_epi32(w_1, (32-7));	\
	i1 = _mm256_srli_epi32(w_1, (7));		\
	o  = _mm256_or_si256(i0, i1);			\
	i0 = _mm256_slli_epi32(w_1, (32-18));	\
	i1 = _mm256_srli_epi32(w_1, (18));		\
	i0 = _mm256_or_si256(i0, i1);			\
	o = _mm256_xor_si256(o, i0);			\
	i1 = _mm256_srli_epi32(w_1, (3));		\
	s0 = _mm256_xor_si256(o, i1);			\
	\
	w_16 = _mm256_add_epi32( w_16, s0);	\
	/* 	 17, 19, 10 operation	*/ \
	i0 = _mm256_slli_epi32(w_14, (32-17));	\
	i1 = _mm256_srli_epi32(w_14, (17));		\
	o  = _mm256_or_si256(i0, i1);			\
	i0 = _mm256_slli_epi32(w_14, (32-19));	\
	i1 = _mm256_srli_epi32(w_14, (19));		\
	i0 = _mm256_or_si256(i0, i1);			\
	o = _mm256_xor_si256(o, i0);			\
	i1 = _mm256_srli_epi32(w_14, (10));		\
	s0 = _mm256_xor_si256(o, i1);			\
	\
	w_16 = _mm256_add_epi32( w_16, s0);	\
	}


inline void sha256_octa_52b(const unsigned char* buf, unsigned char* out) {

	const __m256i *input = (const __m256i *)buf; 

	__m256i a, b, c, d, e, f, g, h, i0, i1, s0, s1;
	__m256i w0, w1, w2, w3, w4, w5, w6, w7, k0;

	a = _mm256_loadu_si256 ((__m256i const*)_H);
	b = _mm256_loadu_si256 ((__m256i const*)(_H+4));
	c = _mm256_loadu_si256 ((__m256i const*)(_H+8));
	d = _mm256_loadu_si256 ((__m256i const*)(_H+12));
	e = _mm256_loadu_si256 ((__m256i const*)(_H+16));
	f = _mm256_loadu_si256 ((__m256i const*)(_H+20));
	g = _mm256_loadu_si256 ((__m256i const*)(_H+24));
	h = _mm256_loadu_si256 ((__m256i const*)(_H+28));

	i0 = _mm256_loadu_si256 ((const __m256i *)_pmask);
	w0 = _mm256_loadu_si256 (input);
	w0 = _mm256_shuffle_epi8(w0, i0);
	w1 = _mm256_loadu_si256 (input + 2);
	w1 = _mm256_shuffle_epi8(w1, i0);
	w2 = _mm256_loadu_si256 (input + 4);
	w2 = _mm256_shuffle_epi8(w2, i0);
	w3 = _mm256_loadu_si256 (input + 6);
	w3 = _mm256_shuffle_epi8(w3, i0);
	w4 = _mm256_loadu_si256 (input + 8);
	w4 = _mm256_shuffle_epi8(w4, i0);
	w5 = _mm256_loadu_si256 (input + 10);
	w5 = _mm256_shuffle_epi8(w5, i0);
	w6 = _mm256_loadu_si256 (input + 12);
	w6 = _mm256_shuffle_epi8(w6, i0);
	w7 = _mm256_loadu_si256 (input + 14);
	w7 = _mm256_shuffle_epi8(w7, i0);


//	pp(w0);pp(w1);pp(w2);pp(w3);pp(w4);pp(w5);pp(w6);pp(w7);

	TRANS8(w0,w1,w2,w3,w4,w5,w6,w7,i0,i1)

	// pp(w0);pp(w1);pp(w2);pp(w3);pp(w4);pp(w5);pp(w6);pp(w7);

	i0 = _mm256_loadu_si256 ((const __m256i *)_pmask);

	// main round function
	ROUND(a,b,c,d,e,f,g,h,w0,0)

// printf("0:\n"); 
// pp(a); pp(b);pp(c);pp(d);pp(e);pp(f);pp(g);pp(h);
// printf("\n");


	ROUND(a,b,c,d,e,f,g,h,w1,1)
	ROUND(a,b,c,d,e,f,g,h,w2,2)
	ROUND(a,b,c,d,e,f,g,h,w3,3)
	ROUND(a,b,c,d,e,f,g,h,w4,4)
	__m256i w12 = _mm256_loadu_si256 (input + 9);
	w12 = _mm256_shuffle_epi8(w12, i0);

	ROUND(a,b,c,d,e,f,g,h,w5,5)
	__m256i w13 = _mm256_loadu_si256 (input + 11);
	w13 = _mm256_shuffle_epi8(w13, i0);

	ROUND(a,b,c,d,e,f,g,h,w6,6)
	__m256i w14 = _mm256_loadu_si256 (input + 13);
	w14 = _mm256_shuffle_epi8(w14, i0);

	ROUND(a,b,c,d,e,f,g,h,w7,7)
	__m256i w15 = _mm256_loadu_si256 (input + 15);
	w15 = _mm256_shuffle_epi8(w15, i0);

	__m256i w8  = _mm256_loadu_si256 (input + 1);
	w8 = _mm256_shuffle_epi8(w8, i0);
	__m256i w9  = _mm256_loadu_si256 (input + 3);
	w9 = _mm256_shuffle_epi8(w9, i0);
	__m256i w10 = _mm256_loadu_si256 (input + 5);
	w10 = _mm256_shuffle_epi8(w10, i0);
	__m256i w11 = _mm256_loadu_si256 (input + 7);
	w11 = _mm256_shuffle_epi8(w11, i0);


// printf("7:\n"); 
// pp(a); pp(b);pp(c);pp(d);pp(e);pp(f);pp(g);pp(h);
// printf("\n");


	// printf("pre:\n");
	// pp(w8);pp(w9);pp(w10);pp(w11);pp(w12);pp(w13);pp(w14);pp(w15);

	TRANS8(w8,w9,w10,w11,w12,w13,w14,w15,i0,i1)

	// w[13..15] determined by the padding for 52-byte=416-bit inputs

	w13 = _mm256_loadu_si256 ((__m256i const*)_P);
	w14 = _mm256_loadu_si256 ((__m256i const*)(_P+4));
	w15 = _mm256_loadu_si256 ((__m256i const*)(_P+8));

	// printf("trans:\n");
	// pp(w8);pp(w9);pp(w10);pp(w11);pp(w12);pp(w13);pp(w14);pp(w15);
	// printf("\n\n");

	ROUND(a,b,c,d,e,f,g,h,w8,8)

	ROUND(a,b,c,d,e,f,g,h,w9,9)
	ROUND(a,b,c,d,e,f,g,h,w10,10)
	ROUND(a,b,c,d,e,f,g,h,w11,11)
	ROUND(a,b,c,d,e,f,g,h,w12,12)
// printf("12:\n"); 
// pp(a); pp(b);pp(c);pp(d);pp(e);pp(f);pp(g);pp(h);
// printf("\n");

	ROUND(a,b,c,d,e,f,g,h,w13,13)

	ROUND(a,b,c,d,e,f,g,h,w14,14)
	ROUND(a,b,c,d,e,f,g,h,w15,15)

	KEY(w16,w0,w1,w9,w14)
	ROUND(a,b,c,d,e,f,g,h,w16,16)

	KEY(w17,w1,w2,w10,w15)
	ROUND(a,b,c,d,e,f,g,h,w17,17)
	KEY(w18,w2,w3,w11,w16)
	ROUND(a,b,c,d,e,f,g,h,w18,18)
	KEY(w19,w3,w4,w12,w17)
	ROUND(a,b,c,d,e,f,g,h,w19,19)
	KEY(w20,w4,w5,w13,w18)
	ROUND(a,b,c,d,e,f,g,h,w20,20)
	KEY(w21,w5,w6,w14,w19)
	ROUND(a,b,c,d,e,f,g,h,w21,21)
	KEY(w22,w6,w7,w15,w20)
	ROUND(a,b,c,d,e,f,g,h,w22,22)
	KEY(w23,w7,w8,w16,w21)
	ROUND(a,b,c,d,e,f,g,h,w23,23)
	KEY(w24,w8,w9,w17,w22)
	ROUND(a,b,c,d,e,f,g,h,w24,24)
	KEY(w25,w9,w10,w18,w23)
	ROUND(a,b,c,d,e,f,g,h,w25,25)
	KEY(w26,w10,w11,w19,w24)
	ROUND(a,b,c,d,e,f,g,h,w26,26)
	KEY(w27,w11,w12,w20,w25)
	ROUND(a,b,c,d,e,f,g,h,w27,27)
	KEY(w28,w12,w13,w21,w26)
	ROUND(a,b,c,d,e,f,g,h,w28,28)
	KEY(w29,w13,w14,w22,w27)
	ROUND(a,b,c,d,e,f,g,h,w29,29)
	KEY(w30,w14,w15,w23,w28)
	ROUND(a,b,c,d,e,f,g,h,w30,30)
	KEY(w31,w15,w16,w24,w29)
	ROUND(a,b,c,d,e,f,g,h,w31,31)
	KEY(w32,w16,w17,w25,w30)
	ROUND(a,b,c,d,e,f,g,h,w32,32)
	KEY(w33,w17,w18,w26,w31)
	ROUND(a,b,c,d,e,f,g,h,w33,33)
	KEY(w34,w18,w19,w27,w32)
	ROUND(a,b,c,d,e,f,g,h,w34,34)
	KEY(w35,w19,w20,w28,w33)
	ROUND(a,b,c,d,e,f,g,h,w35,35)
	KEY(w36,w20,w21,w29,w34)
	ROUND(a,b,c,d,e,f,g,h,w36,36)
	KEY(w37,w21,w22,w30,w35)
	ROUND(a,b,c,d,e,f,g,h,w37,37)
	KEY(w38,w22,w23,w31,w36)
	ROUND(a,b,c,d,e,f,g,h,w38,38)
	KEY(w39,w23,w24,w32,w37)
	ROUND(a,b,c,d,e,f,g,h,w39,39)
	KEY(w40,w24,w25,w33,w38)
	ROUND(a,b,c,d,e,f,g,h,w40,40)
	KEY(w41,w25,w26,w34,w39)
	ROUND(a,b,c,d,e,f,g,h,w41,41)
	KEY(w42,w26,w27,w35,w40)
	ROUND(a,b,c,d,e,f,g,h,w42,42)
	KEY(w43,w27,w28,w36,w41)
	ROUND(a,b,c,d,e,f,g,h,w43,43)
	KEY(w44,w28,w29,w37,w42)
	ROUND(a,b,c,d,e,f,g,h,w44,44)
	KEY(w45,w29,w30,w38,w43)
	ROUND(a,b,c,d,e,f,g,h,w45,45)
	KEY(w46,w30,w31,w39,w44)
	ROUND(a,b,c,d,e,f,g,h,w46,46)
	KEY(w47,w31,w32,w40,w45)
	ROUND(a,b,c,d,e,f,g,h,w47,47)
	KEY(w48,w32,w33,w41,w46)
	ROUND(a,b,c,d,e,f,g,h,w48,48)
	KEY(w49,w33,w34,w42,w47)
	ROUND(a,b,c,d,e,f,g,h,w49,49)
	KEY(w50,w34,w35,w43,w48)
	ROUND(a,b,c,d,e,f,g,h,w50,50)
	KEY(w51,w35,w36,w44,w49)
	ROUND(a,b,c,d,e,f,g,h,w51,51)
	KEY(w52,w36,w37,w45,w50)
	ROUND(a,b,c,d,e,f,g,h,w52,52)
	KEY(w53,w37,w38,w46,w51)
	ROUND(a,b,c,d,e,f,g,h,w53,53)
	KEY(w54,w38,w39,w47,w52)
	ROUND(a,b,c,d,e,f,g,h,w54,54)
	KEY(w55,w39,w40,w48,w53)
	ROUND(a,b,c,d,e,f,g,h,w55,55)
	KEY(w56,w40,w41,w49,w54)
	ROUND(a,b,c,d,e,f,g,h,w56,56)
	KEY(w57,w41,w42,w50,w55)
	ROUND(a,b,c,d,e,f,g,h,w57,57)
	KEY(w58,w42,w43,w51,w56)
	ROUND(a,b,c,d,e,f,g,h,w58,58)
	KEY(w59,w43,w44,w52,w57)
	ROUND(a,b,c,d,e,f,g,h,w59,59)
	KEY(w60,w44,w45,w53,w58)
	ROUND(a,b,c,d,e,f,g,h,w60,60)
	KEY(w61,w45,w46,w54,w59)
	ROUND(a,b,c,d,e,f,g,h,w61,61)
	KEY(w62,w46,w47,w55,w60)
	ROUND(a,b,c,d,e,f,g,h,w62,62)
	KEY(w63,w47,w48,w56,w61)
	ROUND(a,b,c,d,e,f,g,h,w63,63)
// printf("63:\n"); 
// pp(a); pp(b);pp(c);pp(d);pp(e);pp(f);pp(g);pp(h);
// printf("\n");

	w0 = _mm256_loadu_si256 ((__m256i const*)_H);
	a = _mm256_add_epi32( a, w0);
	w1 = _mm256_loadu_si256 ((__m256i const*)_H+1);
	b = _mm256_add_epi32( b, w1);
	w2 = _mm256_loadu_si256 ((__m256i const*)_H+2);
	c = _mm256_add_epi32( c, w2);
	w3 = _mm256_loadu_si256 ((__m256i const*)_H+3);
	d = _mm256_add_epi32( d, w3);
	w4 = _mm256_loadu_si256 ((__m256i const*)_H+4);
	e = _mm256_add_epi32( e, w4);
	w5 = _mm256_loadu_si256 ((__m256i const*)_H+5);
	f = _mm256_add_epi32( f, w5);
	w6 = _mm256_loadu_si256 ((__m256i const*)_H+6);
	g = _mm256_add_epi32( g, w6);
	w7 = _mm256_loadu_si256 ((__m256i const*)_H+7);
	h = _mm256_add_epi32( h, w7);

// pp(a); pp(b);pp(c);pp(d);pp(e);pp(f);pp(g);pp(h);

	TRANS8(a,b,c,d,e,f,g,h,i0,i1)

	// pp(a);pp(b);pp(c);pp(d);pp(e);pp(f);pp(g);pp(h);

	i0 = _mm256_loadu_si256 ((const __m256i *)_pmask);
	a = _mm256_shuffle_epi8(a, i0);
	b = _mm256_shuffle_epi8(b, i0);
	c = _mm256_shuffle_epi8(c, i0);
	d = _mm256_shuffle_epi8(d, i0);
	e = _mm256_shuffle_epi8(e, i0);
	f = _mm256_shuffle_epi8(f, i0);
	g = _mm256_shuffle_epi8(g, i0);
	h = _mm256_shuffle_epi8(h, i0);

	_mm256_storeu_si256((__m256i *)(out), a);
	_mm256_storeu_si256((__m256i *)(out+32), b);
	_mm256_storeu_si256((__m256i *)(out+64), c);
	_mm256_storeu_si256((__m256i *)(out+96), d);
	_mm256_storeu_si256((__m256i *)(out+128), e);
	_mm256_storeu_si256((__m256i *)(out+160), f);
	_mm256_storeu_si256((__m256i *)(out+192), g);
	_mm256_storeu_si256((__m256i *)(out+224), h);


}



// Process the message in successive 512-bit chunks:
// break message into 512-bit chunks
// for each chunk
//     create a 64-entry message schedule array w[0..63] of 32-bit words
//     (The initial values in w[0..63] don't matter, so many implementations zero them here)
//     copy chunk into first 16 words w[0..15] of the message schedule array

//     Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
//     for i from 16 to 63
//         s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
//         s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
//         w[i] := w[i-16] + s0 + w[i-7] + s1

//     Initialize working variables to current hash value:
//     a := h0
//     b := h1
//     c := h2
//     d := h3
//     e := h4
//     f := h5
//     g := h6
//     h := h7

//     Compression function main loop:
//     for i from 0 to 63
//         S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
//         ch := (e and f) xor ((not e) and g)
//         temp1 := h + S1 + ch + k[i] + w[i]
//         S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
//         maj := (a and b) xor (a and c) xor (b and c)
//         temp2 := S0 + maj
 
//         h := g
//         g := f
//         f := e
//         e := d + temp1
//         d := c
//         c := b
//         b := a
//         a := temp1 + temp2

//     Add the compressed chunk to the current hash value:
//     h0 := h0 + a
//     h1 := h1 + b
//     h2 := h2 + c
//     h3 := h3 + d
//     h4 := h4 + e
//     h5 := h5 + f
//     h6 := h6 + g
//     h7 := h7 + h



void sha256_multi_52b(const unsigned char* buf, unsigned char* out, size_t count) {
	size_t ii;
	#pragma omp parallel for
	for (ii = 0; ii < count/8; ii++) {
		sha256_octa_52b(&buf[64*8*ii], &out[32*8*ii]);
	}
}
