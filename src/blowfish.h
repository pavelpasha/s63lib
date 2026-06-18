
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

#include <vector>
#include <string>
#include <cstdint>
#include <exception>
#include <iostream>
#include "assert.h"

namespace s63lib {
class CBlowFish
{
private:

    struct SBlock
    {
        //Constructors
        SBlock(unsigned int l = 0, unsigned int r = 0) : m_uil(l), m_uir(r) {}
        //Copy Constructor
        SBlock(const SBlock& roBlock) : m_uil(roBlock.m_uil), m_uir(roBlock.m_uir) {}
        SBlock& operator^=(SBlock& b) { m_uil ^= b.m_uil; m_uir ^= b.m_uir; return *this; }
        unsigned int m_uil, m_uir;
    };


    // Internal helper that works with any contiguous container
    template<typename Container>
    void encrypt_impl(Container& buf) const {

            if (buf.size() % 8 != 0) {
                // Add padding as per PKCS5
                // Ref: RFC 5652 http://tools.ietf.org/html/rfc5652#section-6.3
                uint8_t paddingLength = 8 - (buf.size() % 8);
                std::vector<uint8_t> padding(paddingLength, static_cast<char>(paddingLength));
                buf.insert(buf.end(), padding.begin(), padding.end());

            }

            size_t n = buf.size();
            assert(n % 8 == 0);
            SBlock work;
            uint8_t* in = reinterpret_cast<uint8_t*>(buf.data());
            for (; n >= 8; n -= 8)
            {
                BytesToBlock(in, work);
                Encrypt(work);
                BlockToBytes(work, in += 8);
            }
    }

    template<typename Container>
    void decrypt_impl(Container& buf, bool remove_padding) const {

        decrypt(reinterpret_cast<uint8_t*>(buf.data()),buf.size());

        if (remove_padding) {
            uint8_t padding_size = buf.back();
            if (padding_size != 0 && padding_size < buf.size())
                buf.resize(buf.size() - padding_size);
        }


    }

public:

	CBlowFish() = default;
	CBlowFish(const std::string& key, const SBlock& roChain = SBlock(0UL, 0UL));

	void setKey(const std::string& key);

    void decrypt(uint8_t* buf, size_t len) const;


    template<typename Container>
    void encrypt(Container& buf) const {
        encrypt_impl(buf);
    }

    template<typename Container>
    void decrypt(Container& buf, bool remove_padding = true) const {
        decrypt_impl(buf, remove_padding);
    }


    // Return by value versions
    template<typename Container>
    Container encrypt(const Container& buf) const {
        Container result = buf;
        encrypt(result);
        return result;
    }

    template<typename Container>
    Container decrypt(const Container& buf, bool remove_padding = true) const {
        Container result = buf;
        decrypt(result, remove_padding);
        return result;
    }
	
	//Resetting the chaining block
	void ResetChain() { m_oChain = m_oChain0; }

	//Private Functions
private:


	unsigned int F(unsigned int ui) const;
	void Encrypt(SBlock&) const;
	void Decrypt(SBlock&) const;

    static void  BytesToBlock(uint8_t const* p, SBlock& b);
    static void BlockToBytes(SBlock const& b, uint8_t* p);

private:
	//The Initialization Vector, by default {0, 0}
	SBlock m_oChain0;
	SBlock m_oChain;
	unsigned int m_auiP[18];
	unsigned int m_auiS[4][256];
    // static const unsigned int scm_auiInitP[18];
    // static const unsigned int scm_auiInitS[4][256];
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

}
#endif // __BLOWFISH_H__
