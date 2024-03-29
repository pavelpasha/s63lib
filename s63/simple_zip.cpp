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

#include "simple_zip.h"

#include <string.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ctime>

#include "zlib/zlib.h"


#define ZIP_MIN_FILE_SIZE 30
#define ZIP_LOCAL_HEADER_SIGNATURE 0x04034b50
#define ZIP_CENTRAL_DIR_SIGNATURE 0x02014b50
#define ZIP_EOCD_RECORD_SIGNATURE 0x06054b50
#define ZIP_LOCAL_HEADER_MIN_SIZE 30
#define ZIP_SIZE_UNKNOWN  0x0800
#define ZIP_ZIP64 0xffffffff

using namespace std;

#pragma pack(push, 1)
struct FileHeader
{
	uint32_t signature = ZIP_LOCAL_HEADER_SIGNATURE;
	uint16_t version_to_extract;
	uint16_t gp_flag;
	uint16_t compression_method;
	uint32_t last_modification_dostime;
	uint32_t crc32;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
	uint16_t filename_len;
	uint16_t extra_field_len;
};

struct CentralDirRecord
{
	uint32_t signature = ZIP_CENTRAL_DIR_SIGNATURE;
	uint16_t version_made_by;
	uint16_t version_to_extract;
	uint16_t gp_flag;
	uint16_t compression_method;
	uint32_t last_modification_dostime;
	uint32_t crc32;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
	uint16_t filename_len;
	uint16_t extra_field_len;
	uint16_t file_comment_len;
	uint16_t disk_num_start;	// Disk number where file starts
	uint16_t intern_file_attr;  // Internal file attributes
	uint32_t extern_file_attr;
	uint32_t rel_offset; // Relative offset of local file header. 
};

struct EOCD
{
	uint32_t signature = ZIP_EOCD_RECORD_SIGNATURE;
	uint16_t number_on_this_disk;
	uint16_t disk_CD;
	uint16_t n_CD;
	uint16_t n_CD_total;
	uint32_t CD_size;
	uint32_t CD_start_offset;
	uint16_t comment_len;
};

#pragma pack(pop)

// Returns current date and time in DOS format
static uint32_t getCurrentDateTime()
{

	std::time_t t = std::time(0);   
	std::tm* ptm = std::localtime(&t);

	uint32_t year = (uint32_t)ptm->tm_year;
	if (year >= 1980)
		year -= 1980;
	else if (year >= 80)
		year -= 80;
	return
		(uint32_t)(((ptm->tm_mday) + (32 * (ptm->tm_mon + 1)) + (512 * year)) << 16) |
		((ptm->tm_sec / 2) + (32 * ptm->tm_min) + (2048 * (uint32_t)ptm->tm_hour));
}

static int uncompressData(const char* const abSrc, size_t nLenSrc, char* abDst, size_t nLenDst)
{
	z_stream zInfo = { 0 };
	zInfo.total_in = zInfo.avail_in = nLenSrc;
	zInfo.total_out = zInfo.avail_out = nLenDst;
	zInfo.next_in = (Bytef*)abSrc;
	zInfo.next_out = (unsigned char*)abDst;

	int nErr, nRet = -1;

	nErr = inflateInit2(&zInfo, -MAX_WBITS);               // zlib function
	if (nErr == Z_OK) {
		nErr = inflate(&zInfo, Z_FINISH);     // zlib function
		if (nErr == Z_STREAM_END) {
			nRet = zInfo.total_out;
		}
	}
	inflateEnd(&zInfo);   // zlib function
	return(nRet); // -1 or len of output
}

static int compressData(const char* const in, size_t in_size, string& out_buffer)
{
	
	const size_t BUFSIZE = 128 * 1024;
	uint8_t temp_buffer[BUFSIZE];

	z_stream strm;
	strm.zalloc = 0;
	strm.zfree = 0;
	strm.next_in = (unsigned char*)in;
	strm.avail_in = in_size;
	strm.next_out = temp_buffer;
	strm.avail_out = BUFSIZE;

	deflateInit2(&strm, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);

	while (strm.avail_in != 0)
	{
		int res = deflate(&strm, Z_NO_FLUSH);
		if (res != Z_OK) return res;
		if (strm.avail_out == 0)
		{
			out_buffer.insert(out_buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
			strm.next_out = temp_buffer;
			strm.avail_out = BUFSIZE;
		}
	}

	int deflate_res = Z_OK;
	while (deflate_res == Z_OK)
	{
		if (strm.avail_out == 0)
		{
			out_buffer.insert(out_buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
			strm.next_out = temp_buffer;
			strm.avail_out = BUFSIZE;
		}
		deflate_res = deflate(&strm, Z_FINISH);
	}

	if(deflate_res != Z_STREAM_END)  return deflate_res;
	out_buffer.insert(out_buffer.end(), temp_buffer, temp_buffer + BUFSIZE - strm.avail_out);
	deflateEnd(&strm);

	return 0;
}



bool SimpleZip::unzip(const std::string& in, std::string& out) {

	size_t len = in.size();
	const char* buf = in.data();
	if (len < ZIP_MIN_FILE_SIZE)
		return false;

	const FileHeader* file_header = reinterpret_cast<const FileHeader*>(buf);

	if (file_header->signature != ZIP_LOCAL_HEADER_SIGNATURE) {
		cout << "wrong zip signature\n";
		return false;
	}

	if (file_header->compression_method != Z_DEFLATED && file_header->compression_method != Z_NO_COMPRESSION) {
		puts("unsupported compression method\n");
		return false;
	}

	const char* data_start_ptr = buf + sizeof(FileHeader) + file_header->extra_field_len + file_header->filename_len;
	uint32_t file_crc = file_header->crc32;
	size_t compressed_size = file_header->compressed_size;
	size_t uncompressed_size = file_header->uncompressed_size;

	if (file_header->gp_flag & ZIP_SIZE_UNKNOWN || compressed_size == 0) {

		// Bad news. The file size is unkown in local file header.
		// But we steel knows where it begins
		// To figure out a file size we got to find the End Of Catalog record at the end of zip file
		// Then read an position of Central Catalog record where we can find a file size finaly

		const char* eocd_pos = findEOCD(buf, len);
		if (0 == eocd_pos) {
			puts("cant find end of dirrectory record\n");
			return false;
		}
		const EOCD* eocd = reinterpret_cast<const EOCD*>(eocd_pos);

		if (eocd->CD_start_offset > len) {
			puts("wrong CD offset value\n");
			return false;
		}

		const CentralDirRecord* cd = reinterpret_cast<const CentralDirRecord*>(buf + eocd->disk_CD + eocd->CD_start_offset);

		if (cd->signature != ZIP_CENTRAL_DIR_SIGNATURE) {
			cout << "wrong central dir signature\n";
			return false;

		}
		file_crc = cd->crc32;
		compressed_size = cd->compressed_size;
		uncompressed_size = cd->uncompressed_size;

	}


	out.resize(uncompressed_size);


	if (file_header->compression_method == Z_DEFLATED) {
		int ret = uncompressData(data_start_ptr, compressed_size, const_cast<char*>(out.data()), uncompressed_size);

		if (ret < 0 || ret != uncompressed_size) {
			puts("erro while decompresing\n");
			return false;
		}
	}
	else { // NO COMPRESSION
		puts("there no compresson\n");
		memcpy(const_cast<char*>(out.data()), data_start_ptr,compressed_size);
	}

	unsigned long  crc = crc32(0L, (const unsigned char*)out.data(), uncompressed_size);
	if (crc != file_crc) {
		puts("wrong crc\n");
		return false;
	}
	
}

bool SimpleZip::zip(const std::string& filename, const std::string& in, std::string& out) {

	if (filename.empty()) {
		puts("Filename can`t be empty\n");
		return false;
	}

	if (in.empty()) {
		puts("Data can`t be empty\n");
		return false;
	}

	if (in.size() >= UINT_MAX) {
		puts("Cell size begger than 4gb? Really?\n");
		return false;
	}

	unsigned long  crc = crc32(0L, (const unsigned char*)in.data(), in.size());
	string compressed;
	int res = compressData(in.data(),in.size(), compressed);

	if (res != Z_OK) {
		return false;
	}


	FileHeader file_header;
	file_header.version_to_extract = 20; 
	file_header.gp_flag = 0x0000; 
	file_header.compression_method = 8;
	file_header.last_modification_dostime = getCurrentDateTime();
	file_header.crc32 = crc;
	file_header.compressed_size = compressed.size();
	file_header.uncompressed_size = in.size();
	file_header.filename_len = filename.size();
	file_header.extra_field_len = 0;

	out.append(reinterpret_cast<char*>(&file_header),sizeof(FileHeader));
	out.append(filename.data(), filename.size());
	out.append(compressed.data(), compressed.size());

	CentralDirRecord central_dir;
	central_dir.version_to_extract = file_header.version_to_extract;
	central_dir.version_made_by = 20;
	central_dir.version_to_extract = file_header.version_to_extract;
	central_dir.gp_flag = file_header.gp_flag;
	central_dir.compression_method = file_header.compression_method;
	central_dir.last_modification_dostime = file_header.last_modification_dostime;
	central_dir.crc32 = file_header.crc32;
	central_dir.compressed_size = file_header.compressed_size;
	central_dir.uncompressed_size = file_header.uncompressed_size;
	central_dir.filename_len = file_header.filename_len;
	central_dir.extra_field_len = file_header.extra_field_len;
	central_dir.file_comment_len = 0;
	central_dir.disk_num_start = 0;	
	central_dir.intern_file_attr = 0;  
	central_dir.extern_file_attr = 0;
	central_dir.rel_offset = 0; 

	out.append(reinterpret_cast<char*>(&central_dir), sizeof(CentralDirRecord));
	out.append(filename.data(), filename.size());

	EOCD eocd;
	eocd.number_on_this_disk = 0;
	eocd.disk_CD = 0;
	eocd.n_CD = 1;
	eocd.n_CD_total = 1;
	eocd.CD_size = sizeof(CentralDirRecord)+central_dir.filename_len;
	eocd.CD_start_offset = sizeof(FileHeader)+filename.size()+compressed.size();
	eocd.comment_len = 0;

	out.append(reinterpret_cast<char*>(&eocd), sizeof(EOCD));

	return true;
}

//void SimpleUnzipper::zipInfo(const std::string& path) {
//
//	
//	SimpleUnzipper zip;
//
//	std::ifstream file(path, std::ios::binary);
//	if (!file.is_open()) {
//		puts("Could not open file for reading\n");
//		return;
//	}
//	file.seekg(0, std::ios::end);
//	size_t len = file.tellg();
//	file.seekg(0);
//	string data(len, 0x0);
//	file.read(data.data(), len);
//	file.close();
//
//	const char* buf = data.data();
//	if (len < ZIP_MIN_FILE_SIZE)
//		return;
//
//	const FileHeader* file_header = reinterpret_cast<const FileHeader*>(buf);
//
//	if (file_header->signature != ZIP_LOCAL_HEADER_SIGNATURE) {
//		cout << "wrong zip signature\n";
//		return;
//	}
//
//	cout << "version to extract " << file_header->version_to_extract << endl;
//	cout << "compression method " << file_header->compression_method << endl;
//	cout << "last mod time " << file_header->last_modification_time << endl;
//	cout << "last mod date " << file_header->last_modification_date << endl;
//	cout << "crc12 " << file_header->crc32 << endl;
//	cout << "compressed size " << file_header->compressed_size << endl;
//	cout << "uncompressed size " << file_header->uncompressed_size << endl;
//	cout << "filename len is: " << file_header->filename_len << endl;
//	cout << "extra field len is: " << file_header->extra_field_len << endl;
//
//	string fname(buf + sizeof(FileHeader), file_header->filename_len);
//	cout << "filename is " << fname.c_str() << endl;
//
//	if (file_header->compression_method != 8) {
//		puts("unsupported compression method\n");
//		return;
//	}
//
//	const char* eocd_pos = findEOCD(buf, len);
//	if (0 == eocd_pos) {
//		puts("cant find end of dirrectory record\n");
//		return;
//	}
//	const EOCD* eocd = reinterpret_cast<const EOCD*>(eocd_pos);
//
//	if (eocd->CD_start_offset > len) {
//		puts("wrong CD offset value\n");
//		return;
//	}
//
//
//	cout << "number_on_this_disk " << eocd->number_on_this_disk << endl;
//	cout << "disk_CD " << eocd->disk_CD << endl;
//	cout << "n_CD " << eocd->n_CD << endl;
//	cout << "n_CD_total " << eocd->n_CD_total << endl;
//	cout << "CD_size " << eocd->CD_size << endl;
//	cout << "CD_start_offset " << eocd->CD_start_offset << endl;
//
//
//	const CentralDirRecord* cd = reinterpret_cast<const CentralDirRecord*>(buf + eocd->disk_CD + eocd->CD_start_offset);
//
//	if (cd->signature != ZIP_CENTRAL_DIR_SIGNATURE) {
//		cout << "wrong central dir signature\n";
//		return;
//
//	}
//
//
//	cout << "version_made_by " << cd->version_made_by << endl;
//	cout << "version_to_extract " << cd->version_to_extract << endl;
//	cout << "gp_flag " << cd->gp_flag << endl;
//	cout << "compression_method " << cd->compression_method << endl;
//	cout << "last_modification_time " << cd->last_modification_time << endl;
//	cout << "last_modification_date " << cd->last_modification_date << endl;
//	cout << "crc32 " << cd->crc32 << endl;
//	cout << "compressed_size " << cd->compressed_size << endl;
//	cout << "uncompressed_size " << cd->uncompressed_size << endl;
//	cout << "filename_len " << cd->filename_len << endl;
//	cout << "extra_field_len " << cd->extra_field_len << endl;
//	cout << "file_comment_len " << cd->file_comment_len << endl;
//	cout << "disk_num_start " << cd->disk_num_start << endl;
//	cout << "intern_file_attr " << cd->intern_file_attr << endl;
//	cout << "extern_file_attr " << cd->extern_file_attr << endl;
//	cout << "rel_offset " << cd->rel_offset << endl;
//	
//
//}

const char* SimpleZip::findEOCD(const char* buf, size_t len) {

	// First of all seek to the end of the buffer minus size of EOCD record size (except signature)
	// There is no use start searching from very end
	buf += (len-18);
	const char* start_pos = buf;
	const size_t max_comment_size = USHRT_MAX;
	while ((start_pos - buf) < max_comment_size) {
		if (*(buf--) == 0x06)
			if (*(buf--) == 0x05)
				if (*(buf--) == 0x4b)
					if (*(buf--) == 0x50)
						return buf+1;
	}

	return nullptr;
}

