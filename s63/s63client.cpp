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

#include "s63client.h"

#include <fstream>

#include "s63utils.hpp"
#include "simple_zip.h"

using key_pair = std::pair<std::string, std::string>;

using namespace std;
using namespace hexutils;

S63Client::S63Client(const std::string& HW_ID, const std::string& M_KEY, const std::string& M_ID): m_mkey(M_KEY), m_mid(M_ID) {

	setHWID(HW_ID);
}


S63Error S63Client::decryptAndUnzipCell(const std::string& in_path, const std::string& out_path) {

	string cellname = in_path.substr(in_path.size() - VALID_CELLNAME_SIZE - 4, VALID_CELLNAME_SIZE);

	if (m_permits.find(cellname) == m_permits.end()) {
		//SSE 21 – Decryption failed no valid cell permit found. Permits may be for another system or new 
		//permits may be required, please contact your supplier to obtain a new licence.”
		printf("There is no permit for basecell %s\n", cellname.c_str());
		return S63_ERR_PERMIT;
	}

	return decryptAndUnzipCell(in_path, m_permits[cellname], out_path);

}

S63Error S63Client::decryptAndUnzipCell(const std::string& in_path, const std::string& cellpermit, const std::string& out_path) {

	if (cellpermit.size() != VALID_CELLPERMIT_SIZE) {
		puts("Wrong permit size\n");
		return S63_ERR_PERMIT;
	}
	bool ok;
	const auto keys = extractCellKeysFromCellpermit(cellpermit, m_hwid, ok);
	if (!ok) {
		return S63_ERR_PERMIT;
	}
	std::string cellKey = hex_to_string(cellpermit.substr(16, 16));
	if (cellKey.size() != 8) {
		return S63_ERR_PERMIT;
	}

	m_bf.setKey(m_hwid6);
	m_bf.decrypt(cellKey);

	return decryptAndUnzipCellByKey(in_path, keys, out_path);

}

bool S63Client::importPermitFile(const std::string& path) {

	std::ifstream file(path);

	if (!file.is_open()) {
		puts("Could not open permit file\n");
		return false;
	}
	string line;
	bool enc = false;
	while (getline(file, line))
	{
		if (enc) {
			if (line.size() < VALID_CELLPERMIT_SIZE) break;

			if (!installCellPermit(line.substr(0, VALID_CELLPERMIT_SIZE))) {
				break;
			};
		}
		else if (line.find(":ENC") == 0) {
			enc = true;
		}
	}

	file.close();
	return true;
}

void S63Client::setHWID(const std::string& HW_ID) {
	if (HW_ID.size() != 5) {
		puts("Bad hw_id\n");
		return;
	}

	m_hwid = HW_ID;
	m_hwid6 = m_hwid + m_hwid[0];
}


bool S63Client::installCellPermit(const std::string& cellpermit) {

	if (!_validateCellPermit(cellpermit, m_hwid6)) {
		return false;
	}

	string cellname = cellpermit.substr(0, VALID_CELLNAME_SIZE);

	m_permits[cellname] = cellpermit;

	printf("Permit for basecell %s succefully installed\n", cellname.c_str());

	return true;
}


std::string S63Client::open(const std::string& path) {
	string cellname = path.substr(path.size() - VALID_CELLNAME_SIZE - 4, VALID_CELLNAME_SIZE);

	if (m_permits.find(cellname) == m_permits.end()) {
		puts("SSE 21 – Decryption failed no valid cell permit found. Permits may be for another system or new \
		permits may be required, please contact your supplier to obtain a new licence.”");
		return {};
	}
	bool ok;
	key_pair keys = S63::extractCellKeysFromCellpermit(m_permits[cellname],m_hwid,ok);

	if (!ok) {
		return {};
	}
	std::string decrypted;

	if (S63::decryptCell(path, keys, decrypted) != S63_ERR_OK) {
		return {};
	}
	std::string unzipped;
	if (!SimpleZip::unzip(decrypted, unzipped)) {
		return {};
	}
	
	return unzipped;
	
}

std::string S63Client::getUserpermit() {

	return createUserPermit(m_mkey,m_hwid,m_mid);


}
