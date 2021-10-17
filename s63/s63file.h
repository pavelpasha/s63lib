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

// It`s more like a memory buffer with file interface, then an actual file implementation.
// I think it`s almost impossible to implement an actual file or stream over a s63 cell
// because of zip format specification. Yeah, we can decrypt cell portionally from any position,
// and read decrypted data piece by piece, not loading all the data ino a memory. 
// But we steel need to unzip it. And there is difficulties begin.
// To locate a file position and read its size into an zip archive, required to read Central Dir record, wich is located almost at the end of file.
// So we anyway need to read and decrypt a whole cell file, and then pass this decrypted buffer to an unzipper. 
class S63File {

public:
	S63File() = default;
	S63File(const std::string& data);
	S63File(std::string&& data);
	S63File(const char* data_prt, std::size_t size);
	int read(char* buffer, std::size_t size);
	inline bool isOpened() const { return !m_data.empty(); }
	inline std::string& data() { return m_data; }
	inline std::size_t tell() const { return m_pos; }
	void seek(size_t pos);
	inline std::size_t getSize() const { return m_data.size(); };
private:
	std::size_t m_pos = 0;
	std::string m_data;
};

