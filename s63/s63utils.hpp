#pragma once
#include <string>
#include <ctime>

namespace hexutils {
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
		return hex_values[hex_digit];

	}

	template <typename I>
	static std::string n2hexstr(I w, size_t hex_len = sizeof(I) << 1) {
		static const char* digits = "0123456789ABCDEF";
		std::string rc(hex_len, '0');
		for (size_t i = 0, j = (hex_len - 1) * 4; i < hex_len; ++i, j -= 4)
			rc[i] = digits[(w >> j) & 0x0f];
		return rc;
	}

	template <typename T>
	static std::string int_to_bytes(T param)
	{
		std::string arrayOfByte(static_cast<int>(sizeof(T)),' ');
		for (int i = 0; i < sizeof(T); ++i)
			arrayOfByte[sizeof(T) -1 - i] = (param >> (i * 8));
		return arrayOfByte;
	}

	static bool is_hex(const std::string& input, size_t offset, size_t len) {
		
		if (len & 1) return false;
		size_t to = (len + offset);
		if (to > input.length()) return false;

		for (size_t i = offset; i < to; ++i) {

			if (hex_value(input[i]) == -1)
				return false;
	
		}
		
		return true;
	}

	static std::string hex_to_string(const std::string& input, size_t offset, size_t len)
	{

		if (len & 1) return "";
		size_t to = (len + offset);
		if (to > input.length()) return "";

		std::string output;
		output.reserve(len / 2);
		for (size_t i = offset; i < to; i += 2) {

			int hi = hex_value(input[i]);
			int lo = hex_value(input[i + 1]);
			if (hi == -1 || lo == -1) {
				break;
			}

			output.push_back(hi << 4 | lo);

		}

		return output;
	}

	static std::string hex_to_string(const std::string& input)
	{
		const auto len = input.length();
		if (len & 1) return "";
		
		return hex_to_string(input,0,input.size());
	}

	

	static std::string string_to_hex(const std::string& input)
	{
		static const char hex_digits[] = "0123456789ABCDEF";

		std::string output;
		output.reserve(input.length() * 2);
		for (unsigned char c : input)
		{
			output.push_back(hex_digits[c >> 4]);
			output.push_back(hex_digits[c & 15]);
		}
		return output;
	}
}


static inline unsigned long swap_bytes(unsigned long val)
{
	return ((((val) & 0xff000000) >> 24) |
			(((val) & 0x00ff0000) >> 8) |
			(((val) & 0x0000ff00) << 8) |
			(((val) & 0x000000ff) << 24));
	
};


/**
 * @brief A very specific, but fast function. 
 * from part of string
 * @param str - std::string .
 * @param from - start index.
 * @param len -  lenght.
 */
static int substr_to_uint(const std::string& str, std::size_t from, std::size_t len)
{
	if (str.size() <= from) return 0;

	const char* c = str.c_str();
	c += from;
	int val = 0;
	size_t counter = 0;
	while (*c && counter < len) {

		if (!isdigit(*c)) return -1;

		val = val * 10 + (*c++ - '0');
		++counter;
	}
	return val;
}

static bool parseYYYYMMDD(const std::string& str, time_t& datetime)
{
	int year = substr_to_uint(str, 0, 4);
	if (year <= 0) {
		return false;
	}
	tm date {};
	date.tm_year = year - 1900;
	int month = substr_to_uint(str, 4, 2);
	if (month <= 0) {
		return false;
	}
	date.tm_mon = month-1;
	int day = substr_to_uint(str, 6, 2);
	if (day <= 0) {
		return false;
	}
	date.tm_mday = day;
	datetime = std::mktime(&date);
	if (datetime < 0)
		return false;

	return true;
};

