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

#include <cstdint>
#include <string>

//This class is not a fully functional zip implementation.
//It was designed to a very specific purpose: zip and unzip 
//a single ENC Cell, according to the S63 standart.
//It supports only ZIP32 with deflate compression method.

class SimpleZip
{
public:
	// Uncompress a zip file from one buffer(in) into another(out)
	static bool unzip(const std::string& in, std::string& out);
	// Compress a buffer(in) with a given filename to a zip archive buffer(out) 
	static bool zip(const std::string& filename, const std::string& in, std::string& out);
	//void zipInfo(const std::string& path);

private:
	static const char* findEOCD(const char* buf, size_t len);
};

