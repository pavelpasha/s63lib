#pragma once
/*
Copyright (c) 2014 Raivis Strogonovs

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <string>

#include "HexPi.h"

//class Blowfish
//{
//public:
//	Blowfish(std::string key = "ABCD");
//
//	void initBoxes();
//	void calcSubKey(std::string keyStr);
//	std::string encrypt(std::string data);
//	std::string decrypt(std::string cryptedData);
//
//
//private:
//	void _decrypt(uint32_t &L, uint32_t &R);
//	void _encyrpt(uint32_t &L, uint32_t &R);
//	uint32_t f(uint32_t x);
//	uint32_t get32Batch(std::string data, unsigned startVal);
//	//uint32_t get32FromChars(std::string data, unsigned startVal);
//	std::string convertToChar(uint32_t L, uint32_t R);
//
//	HexPi hexPi;
//
//	uint32_t P[18];
//	uint32_t S[4][256];
//
//};

class Blowfish
{
public:
	Blowfish(const std::string &key);
	bool init();

	// Padding:
	//
	// Blowfish works on 8-byte blocks. Padding makes it usable even
	// in case where the input size is not in exact 8-byte blocks.
	//
	// If padding is disabled (the default), encrypted() will work only if the
	// input size (in bytes) is a multiple of 8. (If it's not a multiple of 8,
	// encrypted() will return a null bytearray.)
	//
	// If padding is enabled, we increase the input length to a multiple of 8
	// by padding bytes as per PKCS5
	//
	// If padding was enabled during encryption, it should be enabled during
	// decryption for correct decryption (and vice versa).

	void setPaddingEnabled(bool enabled);
	bool isPaddingEnabled() const;

	// Encrypt / decrypt
	std::string encrypted(const std::string& clearText);
	std::string decrypted(const std::string& cipherText);

private:
	// core encrypt/decrypt methods, encrypts/decrypts in-place
	void coreEncrypt(char *x);
	void coreDecrypt(char *x);

	std::string m_key;
	bool m_initialized;
	bool m_paddingEnabled;
	std::string m_parray;
	std::string m_sbox1, m_sbox2, m_sbox3, m_sbox4;
};

#endif // QBLOWFISH_H

