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

#include "s63file.h"

#include <algorithm>

S63File::S63File(const std::string& data) : m_data(data) {


}
S63File::S63File(std::string&& data) : m_data(std::move(data)) {

}

S63File::S63File(const char* data_prt, std::size_t size) : m_data(data_prt,size) {


}
int S63File::read(char* buffer, std::size_t size) {
	int left = m_data.size() - m_pos;
	if (left <= 0) return 0;
	std::size_t ret = std::min(left, (int)size);
	memcpy(const_cast<char*>(m_data.data()+m_pos),buffer, ret);
	m_pos += ret;
	return ret;
}

void S63File::seek(size_t pos) {
	if (pos >= m_data.size()) return;
	m_pos = pos;
}
