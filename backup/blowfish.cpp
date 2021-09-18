#include "blowfish.h"

#include <vector>
#include <cassert>
#include <uchar.h>

#include "blowfish_p.h"

using namespace std;

static int hex_value(unsigned char hex_digit)
{
	static const signed char hex_values[256] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
		-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	};
	int value = hex_values[hex_digit];
	if (value == -1) throw std::invalid_argument("invalid hex digit");
	return value;
}

std::string hex_to_string(const char* input, int len)
{
	
	if (len & 1) throw std::invalid_argument("odd length");

	std::string output;
	output.reserve(len / 2);
	for (int i = 0; i < len; )
	{
		int hi = hex_value(input[i++]);
		int lo = hex_value(input[i++]);
		output.push_back(hi << 4 | lo);
	}
	return output;
}


#include <climits>

template <typename T>
T swap_endian(const unsigned char* source)
{
	static_assert (CHAR_BIT == 8, "CHAR_BIT != 8");

	T dest = 0;
	unsigned char* dst = reinterpret_cast<unsigned char*>(&dest);

	for (size_t k = 0; k < sizeof(T); ++k)
		dst[k] = source[sizeof(T) - k - 1];

	return dest;
}

template <typename T>
void swap_endian(const unsigned char* source, unsigned char* dest)
{
	static_assert (CHAR_BIT == 8, "CHAR_BIT != 8");

	for (size_t k = 0; k < sizeof(T); ++k)
		dest[k] = source[sizeof(T) - k - 1];

}


Blowfish::Blowfish(const string &key)
	: m_key(key)
	, m_initialized(false)
	, m_paddingEnabled(false)
{
}

void Blowfish::setPaddingEnabled(bool enabled)
{
	m_paddingEnabled = enabled;
}

bool Blowfish::isPaddingEnabled() const
{
	return m_paddingEnabled;
}

string Blowfish::encrypted(const string& _clearText)
{
	string clearText(_clearText);
	if (clearText.empty()) {
		return string();
	}

	if (isPaddingEnabled()) {
		// Add padding as per PKCS5
		// Ref: RFC 5652 http://tools.ietf.org/html/rfc5652#section-6.3
		uint8_t paddingLength = 8 - (clearText.size() % 8);
		string paddingBa(paddingLength, static_cast<char>(paddingLength));
		clearText.append(paddingBa);
	}
	else {
		if (clearText.size() % 8 != 0) {
			puts("Cannot encrypt. Clear-text length is not a multiple of 8 and padding is not enabled.");
			return string();
		}
	}

	assert(clearText.size() % 8 == 0);
	if ((clearText.size() % 8 == 0) && init()) {

		string copyBa(clearText.data(), clearText.size());
		for (int i = 0; i < clearText.size(); i += 8) {
			coreEncrypt(&copyBa[0] + i);
		}
		return copyBa;

	}
	return string();
}

string Blowfish::decrypted(const string& cipherText)
{
	if (cipherText.empty()) {
		return string();
	}

	assert(cipherText.size() % 8 == 0);
	if ((cipherText.size() % 8 == 0) && init()) {

		string copyBa(cipherText.data(), cipherText.size());
		for (int i = 0; i < cipherText.size(); i += 8) {
			coreDecrypt(&copyBa[0] + i);
		}

		if (isPaddingEnabled()) {
			// Remove padding as per PKCS5
			uint8_t paddingLength = static_cast<uint8_t>(copyBa.back());
			string paddingBa(paddingLength, static_cast<char>(paddingLength));
			if (copyBa.substr(copyBa.size()-paddingLength) == paddingBa) {
				return copyBa.substr(0,copyBa.length() - paddingLength);
			}
			return string();
		}
		return copyBa;
	}
	return string();
}

/*
  Core encryption code follows. This is an implementation of the Blowfish algorithm as described at:
  http://www.schneier.com/paper-blowfish-fse.html
*/

bool Blowfish::init()
{
	if (m_initialized) {
		return true;
	}

	if (m_key.empty()) {
		puts("Cannot init. Key is empty.");
		return false;
	}


	/*m_sbox1 = hex_to_string(sbox0,sizeof(sbox0)/sizeof(sbox0[0]));
	m_sbox2 = hex_to_string(sbox1, sizeof(sbox1) / sizeof(sbox1[0]));
	m_sbox3 = hex_to_string(sbox2, sizeof(sbox2) / sizeof(sbox2[0]));
	m_sbox4 = hex_to_string(sbox3, sizeof(sbox1) / sizeof(sbox3[0]));
	m_parray = hex_to_string(parray, sizeof(parray) / sizeof(parray[0]));*/

	m_sbox1 = hex_to_string(sbox0, SBOX_SIZE_BYTES * 2);
	m_sbox2 = hex_to_string(sbox1, SBOX_SIZE_BYTES * 2);
	m_sbox3 = hex_to_string(sbox2, SBOX_SIZE_BYTES * 2);
	m_sbox4 = hex_to_string(sbox3, SBOX_SIZE_BYTES * 2);
	m_parray = hex_to_string(parray, PARRAY_SIZE_BYTES * 2);

	/*m_sbox1 = string::fromHex(string::fromRawData(sbox0, SBOX_SIZE_BYTES * 2));
	m_sbox2 = string::fromHex(string::fromRawData(sbox1, SBOX_SIZE_BYTES * 2));
	m_sbox3 = string::fromHex(string::fromRawData(sbox2, SBOX_SIZE_BYTES * 2));
	m_sbox4 = string::fromHex(string::fromRawData(sbox3, SBOX_SIZE_BYTES * 2));
	m_parray = string::fromHex(string::fromRawData(parray, PARRAY_SIZE_BYTES * 2));*/

	const string &key = m_key;
	int keyLength = key.length();
	for (int i = 0; i < PARRAY_SIZE_BYTES; ++i) {
		m_parray[i] = static_cast<char>(static_cast<uint8_t>(m_parray[i]) ^ static_cast<uint8_t>(key[i % keyLength]));
	}

	char seed[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	// Update p-array
	for (int i = 0; i < (PARRAY_SIZE_BYTES / 4); i += 2) {
		coreEncrypt(seed);
		for (int j = 0; j < 8; j++) {
			// P1 = xL; P2 = xR
			m_parray[i * 4 + j] = seed[j];
		}
	}

	// Update s-boxes
	for (int sboxIndex = 1; sboxIndex <= 4; sboxIndex++) {
		string *sbox = 0;
		switch (sboxIndex) {
		case 1: sbox = &m_sbox1; break;
		case 2: sbox = &m_sbox2; break;
		case 3: sbox = &m_sbox3; break;
		case 4: sbox = &m_sbox4; break;
		default: assert(false);
		}
		assert(sbox != 0);

		for (int i = 0; i < (SBOX_SIZE_BYTES / 4); i += 2) {
			coreEncrypt(seed);
			for (int j = 0; j < 8; j++) {
				// S1,1 = xL; S1,2 = xR
				sbox->operator[](i * 4 + j) = seed[j];
			}
		}
	}

	m_initialized = true;
	return true;
}

void Blowfish::coreEncrypt(char *x) // encrypts 8 bytes pointed to by x, result is written to the same location
{
	// Divide x into two 32-bit halves: xL, xR
	char *xL = x;
	char *xR = x + 4;
	unsigned char f_xL_bytes[4] = { 0, 0, 0, 0 };

	for (int i = 0; i < 16; ++i) {

		// xL = xL XOR Pi
		for (int j = 0; j < 4; ++j) {
			// uint8_t old_xL = xL[j];
			xL[j] = static_cast<char>(static_cast<uint8_t>(xL[j]) ^ static_cast<uint8_t>(m_parray[i * 4 + j]));
		}

		// Divide xL into four eight-bit quarters: a, b, c, and d
		uint8_t a = static_cast<uint8_t>(xL[0]);
		uint8_t b = static_cast<uint8_t>(xL[1]);
		uint8_t c = static_cast<uint8_t>(xL[2]);
		uint8_t d = static_cast<uint8_t>(xL[3]);

		// F(xL) = ((S1,a + S2,b mod 2**32) XOR S3,c) + S4,d mod 2**32
		uint32_t s1a = swap_endian<uint32_t>(reinterpret_cast<const unsigned char *>(m_sbox1.data() + a * 4));
		uint32_t s2b = swap_endian<uint32_t>(reinterpret_cast<const unsigned char *>(m_sbox2.data() + b * 4));
		uint32_t s3c = swap_endian<uint32_t>(reinterpret_cast<const unsigned char *>(m_sbox3.data() + c * 4));
		uint32_t s4d = swap_endian<uint32_t>(reinterpret_cast<const unsigned char *>(m_sbox4.data() + d * 4));
		uint32_t f_xL = ((((s1a + s2b) & 0xffffffff) ^ s3c) + s4d) & 0xffffffff;
		swap_endian<uint32_t>(reinterpret_cast<const unsigned char*>(&f_xL), f_xL_bytes);

		// xR = F(xL) XOR xR
		for (int j = 0; j < 4; ++j) {
			xR[j] = static_cast<char>(static_cast<uint8_t>(f_xL_bytes[j]) ^ static_cast<uint8_t>(xR[j]));
		}

		// Swap xL and xR, but not in the last iteration
		if (i != 15) {
			for (int j = 0; j < 4; j++) {
				char temp = xL[j];
				xL[j] = xR[j];
				xR[j] = temp;
			}
		}

	}

	// xR = xR XOR P17
	// xL = xL XOR P18
	for (int j = 0; j < 4; j++) {
		xR[j] = static_cast<char>(static_cast<uint8_t>(xR[j]) ^ static_cast<uint8_t>(m_parray[16 * 4 + j]));
		xL[j] = static_cast<char>(static_cast<uint8_t>(xL[j]) ^ static_cast<uint8_t>(m_parray[17 * 4 + j]));
	}
}

void Blowfish::coreDecrypt(char *x) // decrypts 8 bytes pointed to by x, result is written to the same location
{
	// Divide x into two 32-bit halves: xL, xR
	char *xL = x;
	char *xR = x + 4;
	unsigned char f_xL_bytes[4] = { 0, 0, 0, 0 };

	// xL = xL XOR P18
	// xR = xR XOR P17
	for (int j = 0; j < 4; ++j) {
		xL[j] = static_cast<char>(static_cast<uint8_t>(xL[j]) ^ static_cast<uint8_t>(m_parray[17 * 4 + j]));
		xR[j] = static_cast<char>(static_cast<uint8_t>(xR[j]) ^ static_cast<uint8_t>(m_parray[16 * 4 + j]));
	}

	for (int i = 15; i >= 0; --i) {

		// Swap xL and xR, but not in the first iteration
		if (i != 15) {
			for (int j = 0; j < 4; ++j) {
				char temp = xL[j];
				xL[j] = xR[j];
				xR[j] = temp;
			}
		}

		// Divide xL into four eight-bit quarters: a, b, c, and d
		uint8_t a = static_cast<uint8_t>(xL[0]);
		uint8_t b = static_cast<uint8_t>(xL[1]);
		uint8_t c = static_cast<uint8_t>(xL[2]);
		uint8_t d = static_cast<uint8_t>(xL[3]);

		// F(xL) = ((S1,a + S2,b mod 2**32) XOR S3,c) + S4,d mod 2**32
		uint32_t s1a = swap_endian<uint32_t>(reinterpret_cast<const unsigned char *>(m_sbox1.data() + a * 4));
		uint32_t s2b = swap_endian<uint32_t>(reinterpret_cast<const unsigned char *>(m_sbox2.data() + b * 4));
		uint32_t s3c = swap_endian<uint32_t>(reinterpret_cast<const unsigned char *>(m_sbox3.data() + c * 4));
		uint32_t s4d = swap_endian<uint32_t>(reinterpret_cast<const unsigned char *>(m_sbox4.data() + d * 4));
		uint32_t f_xL = ((((s1a + s2b) & 0xffffffff) ^ s3c) + s4d) & 0xffffffff;
		swap_endian<uint32_t>(reinterpret_cast<const unsigned char*>(&f_xL), f_xL_bytes);

		// xR = F(xL) XOR xR
		for (int j = 0; j < 4; j++) {
			xR[j] = static_cast<char>(static_cast<uint8_t>(f_xL_bytes[j]) ^ static_cast<uint8_t>(xR[j]));
		}

		// xL = xL XOR Pi
		for (int j = 0; j < 4; j++) {
			xL[j] = static_cast<char>(static_cast<uint8_t>(xL[j]) ^ static_cast<uint8_t>(m_parray[i * 4 + j]));
		}

	}
}




//Blowfish::Blowfish(string key)
//{
//	calcSubKey(key);
//}
//
//string Blowfish::encrypt(string data)
//{
//	string cryptedData;
//
//	for (int i = 0; i < data.length(); i += 8)
//	{
//		uint32_t L = get32Batch(data, i);
//		uint32_t R = get32Batch(data, i + 4);
//		_encyrpt(L, R);
//		cryptedData.append(convertToChar(L, R));
//	}
//
//	return cryptedData;
//}
//
//string Blowfish::decrypt(string cryptedData)
//{
//	string data;
//	for (int i = 0; i < cryptedData.length(); i += 8)
//	{
//		uint32_t L = get32Batch(cryptedData, i);
//		uint32_t R = get32Batch(cryptedData, i + 4);
//		_decrypt(L, R);
//		data.append(convertToChar(L, R));
//	}
//
//
//	return data;
//}
//
//
//
//uint32_t Blowfish::get32Batch(string data, unsigned startVal)
//{
//	uint32_t result = 0;
//	for (int i = startVal; i < startVal + 4; ++i)
//	{
//		result <<= 8;
//		if (i < data.length())
//			result |= data[i] & 0xFF;
//	}
//
//	return result;
//}
//
//
//string Blowfish::convertToChar(uint32_t L, uint32_t R)
//{
//	string result;
//	
//	result += char((L >> 24) & 0xFF);
//	result += char((L >> 16) & 0xFF);
//	result += char((L >> 8) & 0xFF);
//	result += char(L & 0xFF);
//
//	result += char((R >> 24) & 0xFF);
//	result += char((R >> 16) & 0xFF);
//	result += char((R >> 8) & 0xFF);
//	result += char(R & 0xFF);
//
//	return result;
//}
//
//void Blowfish::calcSubKey(string keyStr)
//{
//	if (keyStr.length() < 4)
//	{
//		puts("Key must be at least 32 bits long\n");
//		return;
//	}
//
//	initBoxes();
//
//	int keyLength = ceil(keyStr.length() / 4.0);
//
//	vector<uint32_t> key(keyLength);
//	uint32_t *ptr = &key[0];
//	for (int i = 0; i < keyStr.length(); i += 4)
//	{
//		uint32_t tempKey = 0;
//		tempKey |= (uint8_t(keyStr[i]) << 24);
//		if (i + 1 < keyStr.length()) tempKey |= (uint8_t(keyStr[i + 1]) << 16);
//		if (i + 2 < keyStr.length()) tempKey |= (uint8_t(keyStr[i + 2]) << 8);
//		if (i + 3 < keyStr.length()) tempKey |= uint8_t(keyStr[i + 3]);
//		*ptr = tempKey;
//		++ptr;
//	}
//
//
//	for (int i = 0; i < 18; ++i)
//	{
//		P[i] ^= key[i%keyLength];
//	}
//	uint32_t L = 0, R = 0;
//	for (int i = 0; i < 18; i += 2)
//	{
//		_encyrpt(L, R);
//		P[i] = L;
//		P[i + 1] = R;
//	}
//
//	for (int i = 0; i < 4; ++i)
//		for (int j = 0; j < 256; j += 2)
//		{
//			_encyrpt(L, R);
//			S[i][j] = L;
//			S[i][j + 1] = R;
//		}
//}
//
//uint32_t Blowfish::f(uint32_t x)
//{
//	uint32_t h = S[0][x >> 24] + S[1][x >> 16 & 0xff];
//	return (h ^ S[2][x >> 8 & 0xff]) + S[3][x & 0xff];
//}
//
//void Blowfish::_encyrpt(uint32_t &L, uint32_t &R)
//{
//	for (int i = 0; i < 16; i += 2)
//	{
//		L ^= P[i];
//		R ^= f(L);
//		R ^= P[i + 1];
//		L ^= f(R);
//	}
//
//	L ^= P[16];
//	R ^= P[17];
//
//	swap(L, R);
//}
//
//void Blowfish::_decrypt(uint32_t &L, uint32_t &R)
//{
//	for (int i = 16; i > 0; i -= 2)
//	{
//		L ^= P[i + 1];
//		R ^= f(L);
//		R ^= P[i];
//		L ^= f(R);
//	}
//
//	L ^= P[1];
//	R ^= P[0];
//
//	swap(L, R);
//}
//
//void Blowfish::initBoxes()
//{
//	//Initialize P boxes
//	for (int i = 0; i < 18; i++)
//		P[i] = hexPi.Pi[i];
//
//	//Initialize S boxes
//	int i = 18;
//	for (int b = 0; b < 4; b++)
//		for (int j = 0; j < 256; j++)
//			S[b][j] = hexPi.Pi[i++];
//
//}
