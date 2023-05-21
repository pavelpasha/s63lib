#pragma once
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

#include <string>
#include <unordered_map>

#include "blowfish.h"

#define VALID_CELLPERMIT_SIZE 64
#define VALID_CELLNAME_SIZE 8
#define VALID_USERPERMIT_SIZE 28
#define VALID_M_ID_SIZE 2
#define VALID_HW_ID_SIZE 5
#define VALID_M_KEY_SIZE 5
#define VALID_CELL_KEY_SIZE 5

enum S63Error {
	S63_ERR_OK,
	S63_ERR_FILE, 
	S63_ERR_DATA, 
	S63_ERR_PERMIT,
	S63_ERR_KEY,
	S63_ERR_ZIP,
	S63_ERR_CRC
};

class S63 {

public:
	
	static inline bool validateCellPermit(const std::string& permit, const std::string& HW_ID);
	static std::string createUserPermit(const std::string& M_KEY, const std::string& HW_ID, const std::string& M_ID);
	static std::string extractHwIdFromUserpermit(const std::string& userpermit, const std::string& M_KEY);

	static std::string createCellPermit(const std::string& HW_ID, const std::string& CK1, const std::string& CK2, const std::string& cellname, const std::string& expiry_date);
	static std::pair<std::string,std::string> extractCellKeysFromCellpermit(const std::string& cellpermit, const std::string& HW_ID, bool& ok);
	
	// Note, that after being decrypted, cell still need to be uncompressed
	static S63Error decryptCell(const std::string& path, const std::pair<std::string, std::string>& keys, std::string& out_buf);
	static S63Error decryptCell(std::string& buf, const std::string& key);

	static void encryptCell(std::string& buf, const std::string& key);

	static S63Error decryptAndUnzipCellByKey(const std::string& in_path, const std::pair<std::string, std::string>& keys, const std::string& out_path);

protected:
	static bool _validateCellPermit(const std::string& permit, const std::string& HW_ID6);
	static CBlowFish m_bf;
};

bool S63::validateCellPermit(const std::string& permit, const std::string& HW_ID) {
	std::string HW_ID6 = HW_ID + HW_ID[0];
	return _validateCellPermit(permit,HW_ID6);
}
