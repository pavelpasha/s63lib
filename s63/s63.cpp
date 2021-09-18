/*
 * Copyright (c) 2021 Pavel Saenko <pasha03.92@mail.ru>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "s63.h"

#include <iostream>
#include <fstream>

#include "simple_zip.h"
#include "blowfish.h"
#include "s63utils.hpp"
#include "zlib/zlib.h"

#define VALID_ZIP_SIGNATURE 0x04034b50
#define SECONDS_TO_DAYS(S) S/86400

using key_pair = std::pair<std::string, std::string>;

using namespace std;
using namespace hexutils;

CBlowFish S63::m_bf;

bool S63::_validateCellPermit(const std::string& cellpermit, const std::string& HW_ID6) {

	
	if (cellpermit.size() != VALID_CELLPERMIT_SIZE) {
		puts("SSE 12 - CELL PERMIT INCORRECT FORMAT\n");
		return false;
	}
	
	/* CRC32 contains the encrypted check sum for the Cell Permit.It is
		encrypted using the Blowfish algorithm with the Data Client’s
		specific HW_ID and is an 8 byte number.*/

	// 1) Extract the last 16 hex characters (ENC Check Sum) from the Cell Permit.
	// 2) Convert these 16 hex characters to 8 bytes.
	std::string permit_crc32 = hex_to_string(cellpermit, VALID_CELLPERMIT_SIZE - 16, 16);
	if (permit_crc32.size() != 8) {
		return false;
	}

	// 3) Decrypt the crc32 using the Blowfish algorithm with HW_ID6 as the key.
	m_bf.setKey(HW_ID6);
	m_bf.decrypt(permit_crc32);

	unsigned long* crc_from_permit = reinterpret_cast<unsigned long*>(&permit_crc32[0]);
	*crc_from_permit = swap_bytes(*crc_from_permit);

	// 4) Hash the remainder of the Cell Permit as left after ‘a’ using the algorithm CRC32.
	unsigned long calc_crc32 = crc32(0L, (unsigned char*)&cellpermit[0], VALID_CELLPERMIT_SIZE - 16);

	// 5) Compare the crc from permit and calculated one.If they are the same, the Cell Permit is valid.If
	//	they differ, the Cell Permit is corrupt and Cell Permit is not to be used.
	if (*crc_from_permit != calc_crc32) {
		puts("SSE 13 - CELL PERMIT CRC INVALID\n");
		return false;
	}


	// All permit characters except cellname should be convertable to HEX
	// Otherwise the cell permit is incorrect
	if (!is_hex(cellpermit, VALID_CELLNAME_SIZE, VALID_CELLPERMIT_SIZE - VALID_CELLNAME_SIZE)) {
		puts("SSE 12 - CELL PERMIT INCORRECT FORMAT\n");
		return false;
	}


	time_t expiry_time;
	if (!parseYYYYMMDD(cellpermit.substr(8, 8), expiry_time)) {
		puts("SSE 12 - CELL PERMIT INCORRECT FORMAT\n");
		return false;
	}

	time_t t = std::time(0);
	tm* now = std::localtime(&t);
	if (expiry_time < t) {
		puts("SSE 15 - Subscription service has expired. Please contact your data supplier to renew the subscription licence.\n");
	}
	else {
		time_t diff = expiry_time - t;

		if (SECONDS_TO_DAYS(diff) <= 30) {

			puts("SSE 20 - Subscription service will expire in less than 30 days. Please contact your data supplier to renew the subscription licence.\n");
		}

	}

	return true;

}



S63Error S63::decryptCell(std::string& buf, const std::string& key) {

	size_t size = buf.size();
	if (size < 8 || size % 8 != 0) {
		puts("Wrong file size\n");
		return S63_ERR_DATA;
	}

	m_bf.setKey(key);
	m_bf.decrypt((unsigned char*)buf.data(), 8);
	if (*reinterpret_cast<uint32_t*>(buf.data()) != VALID_ZIP_SIGNATURE) {
	
		return S63_ERR_KEY;
	}

	m_bf.decrypt(buf);

	return S63_ERR_OK;
}

void S63::encryptCell(std::string& buf, const std::string& key) {

	m_bf.setKey(key);
	m_bf.encrypt(buf);

}

S63Error S63::decryptCell(const std::string& path, const key_pair& keys, std::string& out_buf) {

	std::ifstream encryptedFile(path, std::ios::binary);

	if (!encryptedFile.is_open()) {
		puts("Could not open encrypted file for reading\n");
		return S63_ERR_FILE;
	}


	encryptedFile.seekg(0, std::ios::end);
	size_t size = encryptedFile.tellg();
	if (size % 8 != 0) {
		puts("Wrong file size\n");
		return S63_ERR_DATA;
	}
	m_bf.setKey(keys.first);
	encryptedFile.seekg(0);

	// To ensure that key is valid, let`s decrypt the first 8 bytes of cell and
	// test it against the valid zip signature. 
	char test_buf[8];
	encryptedFile.read(test_buf, 8);

	m_bf.decrypt((unsigned char*)test_buf, 8);
	if (*reinterpret_cast<uint32_t*>(&test_buf[0]) != VALID_ZIP_SIGNATURE) {

		puts("First key invalid\n");
		m_bf.setKey(keys.second);

		m_bf.decrypt((unsigned char*)test_buf, 8);
		if (*reinterpret_cast<uint32_t*>(&test_buf[0]) != VALID_ZIP_SIGNATURE) {

			puts("SSE 21 - WARNING DECRYPTION FAILED - DECRYPTION KEYS INVALID\n");
			return S63_ERR_KEY;
		}

	}
	encryptedFile.seekg(0);

	// Ok, key is valid. Now read all the whole file an decrypt it
	out_buf.resize(size);
	encryptedFile.read(out_buf.data(), size);
	encryptedFile.close();

	m_bf.decrypt(out_buf);

	return S63_ERR_OK;
}

S63Error S63::decryptAndUnzipCellByKey(const std::string& in_path, const key_pair& keys, const std::string& out_path) {

	std::string decrypted;

	S63Error err = decryptCell(in_path,keys,decrypted);
	if (err != S63_ERR_OK) {
		return err;
	}

	// Cell compressed with zip. So we got to unzip it.
	SimpleZip unz;
	string out_buf;
	if (!unz.unzip(decrypted, out_buf)) {
		puts("Cant unzip cell\n");
		return S63_ERR_ZIP;
	}

	std::ofstream decryptedFile(out_path, std::ios::binary);

	if (!decryptedFile.is_open()) {
		puts("Could not open dencrypted file for writing\n");
		return S63_ERR_FILE;
	}

	decryptedFile.write(out_buf.data(), out_buf.size());
	decryptedFile.close();
	printf("Cell succefully decrypted\n");
	return S63_ERR_OK;
}


std::string S63::createUserPermit(const std::string& M_KEY, const std::string& HW_ID, const std::string& M_ID) {


	if (M_KEY.size() != VALID_M_KEY_SIZE) {
		printf("Invalid M_KEY size. Must be %d characters\n", VALID_M_KEY_SIZE);
		return "";
	}

	if (HW_ID.size() != VALID_HW_ID_SIZE) {
		printf("Invalid HW_ID size. Must be %d characters\n", VALID_HW_ID_SIZE);
		return "";
	}

	if (M_ID.size() != VALID_M_ID_SIZE) {
		printf("Invalid M_ID size. Must be %d characters\n", VALID_M_ID_SIZE);
		return "";
	}

	//a) Encrypt HW_ID using the Blowfish algorithm with M_KEY as the key.
	string encrypted_hwid = HW_ID;
	m_bf.setKey(M_KEY);
	m_bf.encrypt(encrypted_hwid);
	//b) Convert the resultant value to a 16 characterhexadecimal string.Any alphabetic character
	//should be in upper case.
	string userpermit = string_to_hex(encrypted_hwid);
	userpermit.reserve(VALID_USERPERMIT_SIZE);

	//c) Hash the 16 hexadecimal characters using the algorithm CRC32
	unsigned long calc_crc32 = crc32(0L, (unsigned char*)userpermit.data(), 16);
	
	//d) Convert output from ‘c’ to an 8 character hexadecimal string.Any alphabetic characters
	//should be in upper case.This is the Check Sum
	string hex_crc = n2hexstr(calc_crc32);

	//e) Append to ‘b’ the output from ‘d’.
	userpermit += std::move(hex_crc);

	//f) Convert the M_ID to a 4 character string.Any alphabetic characters should be in upper case.
	//g) Append to ‘e’ the output from ‘f’.This is the User Permit.
	userpermit += string_to_hex(M_ID);

	return userpermit;

}

std::string S63::extractHwIdFromUserpermit(const std::string& userpermit, const std::string& M_KEY) {

	// Example: Userpermit Structure
	//        16              8         4
	// |73871727080876A0| |7E450C04|  |3031|
	//        |               |			|
	//  Encrypted HW_ID      CRC       M_ID

	if (userpermit.size() != VALID_USERPERMIT_SIZE) {
		puts("Invalid userpermit size\n");
		return "";
	}

	// Check if userpermit contains only HEX symbols
	if (!is_hex(userpermit,0, VALID_USERPERMIT_SIZE)) {
		puts("SSE 17 - WARNING INVALID USERPERMIT\n");
		return "";
	}

	if (M_KEY.size() != VALID_M_KEY_SIZE) {
		printf("Invalid M_KEY size. Must be %d characters\n", VALID_M_KEY_SIZE);
		return "";
	}


	//a) Extract M_ID(4 hex characters) from the User Permit. 
	// We already have M_KEY in this procedure, so skip this step

	//b) Extract the Check Sum(8 hex characters) from the User Permit.
	std::string permit_crc32 = hex_to_string(userpermit, VALID_USERPERMIT_SIZE - 12, 8);
	if (permit_crc32.size() != 4) {
		puts("SSE 17 - WARNING INVALID USERPERMIT\n");
		return "";
	}

	//c) Hash the Encrypted HW_ID(the first 16 characters of the User Permit) using the algorithm CRC32.
	unsigned long cacl_crc32 = crc32(0L, reinterpret_cast<const unsigned char*>(userpermit.data()), 16);

	//d) Compare the outputs of ‘b’ and ‘c’.If they are identical, the User Permit is valid.If the two results
	// differ the User Permit is invalid and the HW_ID cannot be obtained.
	cacl_crc32 = swap_bytes(cacl_crc32);
	if (0 != std::memcmp(permit_crc32.data(), &cacl_crc32, sizeof(unsigned long))) {
		puts("SSE 17 - WARNING INVALID USERPERMIT\n");
		return "";
	}

	//e) If the User Permit is valid, convert the Encrypted HW_ID to 8 bytes.
	string hw_id = hex_to_string(userpermit, 0, 16);
	if (hw_id.size() != 8) {
		puts("SSE 17 - WARNING INVALID USERPERMIT\n");
		return "";
	}

	//f) Decrypt the Encrypted HW_ID using the Blowfish algorithm with M_KEY as the key.The output will
	//be HW_ID.
	m_bf.setKey(M_KEY);
	m_bf.decrypt(hw_id);

	if (hw_id.size() != VALID_HW_ID_SIZE) {
		puts("SSE 17 - WARNING INVALID USERPERMIT\n");
		return "";
	}

	return hw_id;

}


std::string S63::createCellPermit(const std::string& HW_ID, const std::string& CK1, const std::string& CK2, const std::string& cellname, const std::string& expiry_date) {

	if (cellname.size() != VALID_CELLNAME_SIZE) {
		printf("Invalid CellName size. Must be %d characters\n", VALID_CELLNAME_SIZE);
		return "";
	}
	if (HW_ID.size() != VALID_HW_ID_SIZE) {
		printf("Invalid HW_ID size. Must be %d characters\n", VALID_HW_ID_SIZE);
		return "";
	}

	if (CK1.size() != VALID_CELL_KEY_SIZE || CK2.size() != VALID_CELL_KEY_SIZE) {
		printf("Invalid VALID_CELL_KEY_SIZE size. Must be %d characters\n", VALID_CELL_KEY_SIZE);
		return "";
	}

	if (expiry_date.size() != 8 ) {
		printf("Invalid Expity date size. Must be %d characters\n", 8);
		return "";
	}
	std::time_t expiry_time;
	if (!parseYYYYMMDD(expiry_date, expiry_time)) {
		puts("Invalid expiry date string. Must be in YYYYMMDD format and correct\n");
		return false;
	}
	string cellpermit = cellname;
	cellpermit.reserve(VALID_CELLPERMIT_SIZE);
	//a) Remove the file extension from the name of the ENC file.This leaves 8 characters and is the Cell Name of the Cell Permit.
	// This procedure takes cellname without extension 
	//b) Append the licence Expiry Date, in the format YYYYMMDD, to the Cell Name from ‘a’.
	cellpermit.append(expiry_date);
	//c) Append the first byte of HW_ID to the end of HW_ID to form a 6 byte HW_ID(called HW_ID6).This is
	//to create a 48 bit key to encrypt the cell keys.
	string HW_ID6 = HW_ID + HW_ID[0];
	//d) Encrypt Cell Key 1 using the Blowfish algorithm with HW_ID6 from ‘c’ as the key to create ECK1.
	//e) Convert ECK1 to 16 hexadecimal characters.Any alphabetic character is to be in upper case.
	//f) Append to ‘b’ the output from ‘e’.
	//h) Convert ECK2 to 16 hexadecimal characters.Any alphabetic characters are to be in upper case.
	//i) Append to ‘f’ the output from ‘h’
	m_bf.setKey(HW_ID6);
	cellpermit += string_to_hex(m_bf.encryptConst(CK1));
	cellpermit += string_to_hex(m_bf.encryptConst(CK2));
	
	//j) Hash the output from ‘i’ using the algorithm CRC32.Note the hash is computed after it has been
	//converted to a hex string as opposed to the User Permit where the hash is computed on the raw binary data.
	unsigned long calc_crc32 = crc32(0L, (unsigned char*)&cellpermit[0], VALID_CELLPERMIT_SIZE - 16);
	calc_crc32 = swap_bytes(calc_crc32);
	//k) Encrypt the hash(output from ‘j’) using the Blowfish algorithm with HW_ID6 as the key.
	m_bf.setKey(HW_ID6);
	string crc(reinterpret_cast<const char*>(&calc_crc32),4);
	m_bf.encrypt(crc);
	cellpermit += string_to_hex(crc);

	//l) Convert output from ‘k’ to a 16 character hexadecimal string.Any alphabetic character is to be in upper case.This forms the ENC Check Sum.
	//m) Append to ‘i’ the output from ‘l’.This is the Cell Permit

	return cellpermit;

}

std::pair<std::string, std::string> S63::extractCellKeysFromCellpermit(const std::string& cellpermit, const std::string& HW_ID, bool& ok) {
	pair<string, string> cell_keys;

	if (HW_ID.size() != VALID_HW_ID_SIZE) {
		printf("Invalid HW_ID size. Must be %d characters\n", VALID_HW_ID_SIZE);
		ok = false;
		return cell_keys;
	}

	if (!validateCellPermit(cellpermit, HW_ID)) {
		puts("Invalid cellpermit\n");
		ok = false;
		return cell_keys;
	}

	string ECK1 = hex_to_string(cellpermit.substr(16, 16));
	string ECK2 = hex_to_string(cellpermit.substr(32, 16));

	if (ECK1.size() != 8 || ECK2.size() != 8) {
		return cell_keys;
	}
	string HW_ID6 = HW_ID + HW_ID[0];
	m_bf.setKey(HW_ID6);

	m_bf.decrypt(ECK1);
	m_bf.decrypt(ECK2);
	cell_keys.first  = std::move(ECK1);
	cell_keys.second = std::move(ECK2);
	ok = true;
	return cell_keys;

}

