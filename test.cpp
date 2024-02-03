#include <stdio.h>
#include <stdint.h>

#include <cstring>

#include <iostream>
#include <vector>
#include <array>

#include <chrono>
#include <thread>
#include <openssl/evp.h>

#include <immintrin.h>

/* AES-128 simple implementation template and testing */

/*
Author: Naoki Yoshida, yoshinao@fit.cvut.cz
Template: Jiri Bucek 2017
AES specification:
http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/

/* AES Constants */

__m128i AES_KEY_128;
// forward sbox
const uint8_t SBOX[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
// key exansion round constant
const uint8_t rCon[12] = {
	0x8d,
	0x01,
	0x02,
	0x04,
	0x08,
	0x10,
	0x20,
	0x40,
	0x80,
	0x1b,
	0x36,
};

uint32_t TBOX[4][256];
bool TBOX_init = false;

/* AES state type */
typedef uint32_t t_state[4];

inline uint32_t word(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3)
{
	return a0 | (uint32_t)a1 << 8 | (uint32_t)a2 << 16 | (uint32_t)a3 << 24;
}

inline uint8_t wbyte(uint32_t w, int pos)
{
	return (w >> (pos * 8)) & 0xff;
}

inline uint32_t setbyte(uint32_t w, int pos, uint8_t b)
{
	return (w & ~(0xff << (pos * 8))) | (uint32_t)b << (pos * 8);
}

// **************** AES  functions ****************
inline uint32_t subWord(uint32_t w)
{
	return word(SBOX[wbyte(w, 0)], SBOX[wbyte(w, 1)], SBOX[wbyte(w, 2)], SBOX[wbyte(w, 3)]);
}
// Done
void subBytes(t_state &s)
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			s[i] = setbyte(s[i], j, SBOX[wbyte(s[i], j)]);
		}
	}
}
// Done
inline void shiftRows(t_state &s)
{
	t_state tmp;
	for (int i = 0; i < 4; i++)
	{
		tmp[i] = word(wbyte(s[i], 0), wbyte(s[(i + 1) % 4], 1), wbyte(s[(i + 2) % 4], 2), wbyte(s[(i + 3) % 4], 3));
	}
	memcpy(s, tmp, sizeof(t_state));
}

inline uint8_t xtime(uint8_t &a)
{
	if (a & 0x80)
		return (a << 1) ^ 0x1b;
	else
		return a << 1;
}

// Done
void mixColumns(t_state s)
{

	for (int i = 0; i < 4; i++)
	{
		uint8_t s0 = wbyte(s[i], 0);
		uint8_t s1 = wbyte(s[i], 1);
		uint8_t s2 = wbyte(s[i], 2);
		uint8_t s3 = wbyte(s[i], 3);

		uint8_t r0 = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
		uint8_t r1 = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
		uint8_t r2 = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
		uint8_t r3 = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);

		s[i] = word(r0, r1, r2, r3);
	}
}

uint32_t RotWord(uint32_t word)
{
	return (word >> 8) | (word << 24);
}

/*
 * Key expansion from 128bits (4*32bit)
 * to 11 round keys (11*4*32b)
 * each round key is 4*32b
 */
void expandKey(const uint8_t k[16], uint32_t ek[44])
{
	for (int i = 0; i < 4; i++)
	{
		ek[i] = word(k[i * 4], k[i * 4 + 1], k[i * 4 + 2], k[i * 4 + 3]);
	}

	for (int i = 4; i < 44; i++)
	{
		uint32_t temp = ek[i - 1];
		if (i % 4 == 0)
		{
			temp = subWord(RotWord(temp)) ^ rCon[i / 4];
		}
		ek[i] = ek[i - 4] ^ temp;
	}
}

// __m128i AES_ASSIST(__m128i temp1, __m128i temp2)
// {
// 	__m128i temp3;

// 	temp2 =
// 			temp3 = _mm_slli_si128(temp1, 0x4); // shift left by 4 bytes
// 	temp1 = _mm_xor_si128(temp1, temp3);		// xor with shifted temp1
// 	temp3 = _mm_slli_si128(temp3, 0x4);
// 	temp1 = _mm_xor_si128(temp1, temp3);
// 	temp3 = _mm_slli_si128(temp3, 0x4);
// 	temp1 = _mm_xor_si128(temp1, temp3);
// 	temp1 = _mm_xor_si128(temp1, temp2);
// 	return temp1;
// }

inline void key_expansion_eas_2(const __m128i &key, __m128i expKey[11])
{ // __m128i [11] expKey
	_mm_storeu_si128(&expKey[0], key);

	__m128i prevkey, keygen_out, temp3;
	prevkey = key;

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x1);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word

	temp3 = _mm_slli_si128(prevkey, 0x4);	 // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey); //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[1], prevkey);

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x2);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word

	temp3 = _mm_slli_si128(prevkey, 0x4);	 // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey); //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[2], prevkey);

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x4);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word
	temp3 = _mm_slli_si128(prevkey, 0x4);			  // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey);		  //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[3], prevkey);

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x8);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word
	temp3 = _mm_slli_si128(prevkey, 0x4);			  // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey);		  //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[4], prevkey);

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x10);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word
	temp3 = _mm_slli_si128(prevkey, 0x4);			  // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey);		  //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[5], prevkey);

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x20);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word
	temp3 = _mm_slli_si128(prevkey, 0x4);			  // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey);		  //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[6], prevkey);

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x40);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word
	temp3 = _mm_slli_si128(prevkey, 0x4);			  // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey);		  //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[7], prevkey);

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x80);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word
	temp3 = _mm_slli_si128(prevkey, 0x4);			  // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey);		  //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[8], prevkey);

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x1b);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word
	temp3 = _mm_slli_si128(prevkey, 0x4);			  // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey);		  //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[9], prevkey);

	keygen_out = _mm_aeskeygenassist_si128(prevkey, 0x36);
	keygen_out = _mm_shuffle_epi32(keygen_out, 0xff); // copy them to 4 word
	temp3 = _mm_slli_si128(prevkey, 0x4);			  // shift left by 4 bytes stored in ot tmp3
	prevkey = _mm_xor_si128(temp3, prevkey);		  //
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	temp3 = _mm_slli_si128(temp3, 0x4);
	prevkey = _mm_xor_si128(temp3, prevkey);
	prevkey = _mm_xor_si128(prevkey, keygen_out);
	_mm_storeu_si128(&expKey[10], prevkey);
}

/* Adding expanded round key (prepared before) */
inline void addRoundKey(t_state s, const uint32_t ek[], short index)
{
	for (int i = 0; i < 4; i++)
	{
		s[i] = s[i] ^ ek[index + i];
	}
}

void TBOX_prep()
{
	for (int i = 0; i < 256; i++)
	{
		uint8_t s = SBOX[i];
		TBOX[0][i] = word(xtime(s), s, s, xtime(s) ^ s);
		TBOX[1][i] = word(xtime(s) ^ s, xtime(s), s, s);
		TBOX[2][i] = word(s, xtime(s) ^ s, xtime(s), s);
		TBOX[3][i] = word(s, s, xtime(s) ^ s, xtime(s));
	}
	TBOX_init = true;
}

inline void TBOX_Sbytes_MixCols_ShiftRow(t_state &s)
{
	t_state tmp;
	for (int i = 0; i < 4; i++)
	{
		tmp[i] = TBOX[0][wbyte(s[i], 0)] ^ TBOX[1][wbyte(s[(i + 1) % 4], 1)] ^ TBOX[2][wbyte(s[(i + 2) % 4], 2)] ^ TBOX[3][wbyte(s[(i + 3) % 4], 3)];
	}
	memcpy(s, tmp, sizeof(t_state));
}

inline void aes(const uint8_t *in, uint8_t *out, const uint32_t *expKey)
{
	//... Initialize ...
	unsigned short round = 0;
	t_state state;
	for (int i = 0; i < 4; i++)
	{
		state[i] = word(in[4 * i], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
	}

	addRoundKey(state, expKey, 0);

	for (round = 1; round < 10; round++)
	{
		TBOX_Sbytes_MixCols_ShiftRow(state);
		addRoundKey(state, expKey, 4 * round);
	}

	subBytes(state);
	shiftRows(state);
	addRoundKey(state, expKey, 40);
	//... Finalize ...
	for (int i = 0; i < 4; i++)
	{
		out[4 * i + 0] = wbyte(state[i], 0);
		out[4 * i + 1] = wbyte(state[i], 1);
		out[4 * i + 2] = wbyte(state[i], 2);
		out[4 * i + 3] = wbyte(state[i], 3);
	}
}

inline void aes_2(const __m128i &in, const __m128i roundkey[11], __m128i &out)
{
	__m128i state = _mm_xor_si128(in, roundkey[0]);
	state = _mm_aesenc_si128(state, roundkey[1]);
	state = _mm_aesenc_si128(state, roundkey[2]);
	state = _mm_aesenc_si128(state, roundkey[3]);
	state = _mm_aesenc_si128(state, roundkey[4]);
	state = _mm_aesenc_si128(state, roundkey[5]);
	state = _mm_aesenc_si128(state, roundkey[6]);
	state = _mm_aesenc_si128(state, roundkey[7]);
	state = _mm_aesenc_si128(state, roundkey[8]);
	state = _mm_aesenc_si128(state, roundkey[9]);
	out = _mm_aesenclast_si128(state, roundkey[10]);
}

void OpenSslAES(uint8_t *in, uint8_t *out, const uint8_t *key)
{
	const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes-128-ecb");
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int outlen;

	EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, out, &outlen, in, 16);
	EVP_EncryptFinal_ex(ctx, out + outlen, NULL);
	EVP_CIPHER_CTX_free(ctx);
	// AES_KEY aesKey;
	// AES_set_encrypt_key(key, 128, &aesKey);
	// AES_encrypt(in, out, &aesKey);
}

//****************************
// MAIN function: AES testing
//****************************

using namespace std;
int main()
{
	int test_failed = 0;

	vector<long> tests = {1'000'000, 10'000'000};

	for (auto test_count : tests)
	{

		vector<array<uint8_t, 16>> inputs(test_count);
		vector<array<uint8_t, 16>> outputs(test_count);

		const uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
		uint32_t expKey[11 * 4];

		TBOX_prep();

		expandKey(key, expKey);

		for (int i = 0; i < test_count; i++)
		{
			for (int j = 0; j < 16; j++)
			{
				inputs[i][j] = rand() % 256;
			}
		}

		__m128i Keyexpanded[11];
		key_expansion_eas_2(_mm_loadu_si128((__m128i *)key), Keyexpanded);
		uint32_t expKey_temp[11 * 4];

		for (int i = 0; i < 11; i++)
		{
			_mm_storeu_si128((__m128i *)&expKey_temp[i * 4], Keyexpanded[i]);
		}

		// print expKey and expKey_temp to compare
		auto start_time = std::chrono::high_resolution_clock::now();
		for (long i = 0; i < test_count; i++)
		{
			// aes(inputs[i].data(), outputs[i].data(), expKey);

			__m128i in = _mm_loadu_si128((__m128i *)inputs[i].data());
			__m128i out;
			aes_2(in, Keyexpanded, out);
			_mm_storeu_si128((__m128i *)outputs[i].data(), out);
		}
		auto end_time = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

		std::cout << "Time taken for " << test_count << " AES encryptions: " << duration << " milliseconds" << std::endl;

		array<uint8_t, 16> out_test;
		for (long i = 0; i < test_count; i++)
		{
			OpenSslAES(inputs[i].data(), out_test.data(), key);
			if (out_test != outputs[i])
			{
				// print output and also out_test
				for (int i = 0; i < 16; i++)
				{
					printf("%02x ", outputs[i][i]);
				}
				printf("\n");
				for (int i = 0; i < 16; i++)
				{
					printf("%02x ", out_test[i]);
				}
				printf("\n");
				test_failed = 1;
				break;
			}
		}
		if (test_failed)
			printf("FAILED!!!!!!!!!!!!!!\n");
		else
			printf("OpenSSL AES matches!\n");
	}

	return 0;
}