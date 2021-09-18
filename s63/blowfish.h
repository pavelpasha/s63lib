
////////////////////////////////////////////////////////////////////////////
/////
//// Blowfish.h Header File
///
//    BLOWFISH ENCRYPTION ALGORITHM
//
//    Encryption and Decryption of Byte Strings using the Blowfish Encryption Algorithm.
//    Blowfish is a block cipher that encrypts data in 8-byte blocks. The algorithm consists
//    of two parts: a key-expansion part and a data-ancryption part. Key expansion converts a
//    variable key of at least 1 and at most 56 bytes into several subkey arrays totaling
//    4168 bytes. Blowfish has 16 rounds. Each round consists of a key-dependent permutation,
//    and a key and data-dependent substitution. All operations are XORs and additions on 32-bit words.
//    The only additional operations are four indexed array data lookups per round.
//    Blowfish uses a large number of subkeys. These keys must be precomputed before any data
//    encryption or decryption. The P-array consists of 18 32-bit subkeys: P0, P1,...,P17.
//    There are also four 32-bit S-boxes with 256 entries each: S0,0, S0,1,...,S0,255;
//    S1,0, S1,1,...,S1,255; S2,0, S2,1,...,S2,255; S3,0, S3,1,...,S3,255;
//
//    The previous ciphertext block is usually stored in an Initialization Vector (IV).
//    An Initialization Vector of zero is commonly used for the first block, though other
//    arrangements are also in use.



#ifndef __BLOWFISH_H__
#define __BLOWFISH_H__

#include <string>

//Block Structure
struct SBlock
{
	//Constructors
	SBlock(unsigned int l = 0, unsigned int r = 0) : m_uil(l), m_uir(r) {}
	//Copy Constructor
	SBlock(const SBlock& roBlock) : m_uil(roBlock.m_uil), m_uir(roBlock.m_uir) {}
	SBlock& operator^=(SBlock& b) { m_uil ^= b.m_uil; m_uir ^= b.m_uir; return *this; }
	unsigned int m_uil, m_uir;
};

class CBlowFish
{
public:

	CBlowFish() = default;
	CBlowFish(const std::string& key, const SBlock& roChain = SBlock(0UL, 0UL));

	void setKey(const std::string& key);

	void decrypt(std::string& buf, bool remove_padding = true) const;
	inline std::string decryptConst(const std::string& buf, bool remove_padding = true) const;
	void decrypt(unsigned char* buf, size_t len) const;

	void encrypt(std::string& buf) const;
	inline std::string encryptConst(const std::string& buf) const;
	
	//Resetting the chaining block
	void ResetChain() { m_oChain = m_oChain0; }

	//Private Functions
private:
	unsigned int F(unsigned int ui) const;
	void Encrypt(SBlock&) const;
	void Decrypt(SBlock&) const;

private:
	//The Initialization Vector, by default {0, 0}
	SBlock m_oChain0;
	SBlock m_oChain;
	unsigned int m_auiP[18];
	unsigned int m_auiS[4][256];
	static const unsigned int scm_auiInitP[18];
	static const unsigned int scm_auiInitS[4][256];
};

//Extract low order byte
inline unsigned char extract_byte(unsigned int ui)
{
	return (unsigned char)(ui & 0xff);
}

//Function F
inline unsigned int CBlowFish::F(unsigned int ui) const
{
	return ((m_auiS[0][extract_byte(ui >> 24)] + m_auiS[1][extract_byte(ui >> 16)]) ^ m_auiS[2][extract_byte(ui >> 8)]) + m_auiS[3][extract_byte(ui)];
}


inline std::string CBlowFish::encryptConst(const std::string& buf) const {
	std::string ret(buf);
	encrypt(ret);
	return ret;
}

inline std::string CBlowFish::decryptConst(const std::string& buf, bool remove_padding) const {
	std::string ret(buf);
	decrypt(ret,remove_padding);
	return ret;
}

#endif // __BLOWFISH_H__
