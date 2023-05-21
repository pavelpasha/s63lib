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

#include "s63.h"

class S63Client : public S63
{
public:
	S63Client(const std::string& HW_ID, const std::string& M_KEY, const std::string& M_ID);
	inline const std::string& getHWID() const {
		return m_hwid;
	}
	inline const std::string& getMID() const {
		return m_mid;
	}
	inline const std::string& getMKEY() const {
		return m_mkey;
	}
	void setHWID(const std::string& HW_ID);
	inline void setMID(const std::string& M_ID)  { m_mid = M_ID; }
	inline void setMKEY(const std::string& M_KEY) { m_mkey = M_KEY; }

	bool installCellPermit(const std::string& cellpermit);
	bool importPermitFile(const std::string& path);

	std::string getUserpermit();

	// Opens a s63 file, finds a corresponding cellpermit among installed,
	// then decrypted and unziped cell retuns as a memory buffer (yeah, string used just as a byte array)
	std::string open(const std::string& path);

	S63Error decryptAndUnzipCell(const std::string& in_path, const std::string& out_path);
	S63Error decryptAndUnzipCell(const std::string& in_path, const std::string& cellpermit, const std::string& out_path);
	
private:
	std::string m_mkey;
	std::string m_mid;
	std::string m_hwid;
	std::string m_hwid6;
	std::unordered_map <std::string, std::string> m_permits;
};

