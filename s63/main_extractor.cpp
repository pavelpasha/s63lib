#include <iostream>
#include <fstream>
#include <cassert>
#include <filesystem>
#include <regex>

#include "INIReader.h"
#include "blowfish.h"
#include "s63Client.h"
#include "simple_zip.h"
#include "s63utils.hpp"

using namespace std;
using namespace hexutils;

static void WriteFileWithENCnames(std::filesystem::path P, std::vector<std::string> EncFileNames)
{
	P /= "s57filenames.txt";
	std::ofstream ofs(P);
	for (auto& fn : EncFileNames)
	{
		ofs << fn << std::endl;
	}

	ofs.close();
}

//returns true if emptry directory otherwise false
static bool WipeEmptyDirs(std::filesystem::path P)
{
	if (!std::filesystem::is_directory(P))
	{
		return false;
	}

	int n = 0;
	for (auto& p : std::filesystem::directory_iterator(P))
	{
		bool e = WipeEmptyDirs(p);
		if (e)
		{
			std::filesystem::remove(p);
		}

		++n;
	}

	return std::filesystem::is_empty(P);
}

int main(int argc, char* argv[])
{
	std::string projectIniFile = "./configs/msd5.ini"; //Assuming execution path in root source dir
	INIReader reader(projectIniFile);

	if (reader.ParseError() < 0)
	{
		std::cout << "Can't load project ini file:" << projectIniFile << "\n";
		return 1;
	}

	//get the keys
	std::string HW_ID = reader.Get("Keys", "HW_ID", "?"); 
	std::string M_KEY = reader.Get("Keys", "M_KEY", "?");
	std::string M_ID = reader.Get("Keys", "M_ID", "?");
	
	S63Client s63(HW_ID, M_KEY, M_ID);

	//get the directories
	std::string dir_in = reader.Get("Dirs", "in", "?");
	std::string dir_out = reader.Get("Dirs", "out", "?");

	std::string permitfile = reader.Get("Dirs", "permitfile", "?");
	bool importOk = s63.importPermitFile(permitfile);

	std::cout << "Import Permitfile OK:" << importOk << " File:" << permitfile << std::endl;
	if (!importOk)
	{
		return -2;
	}

	std::vector<std::string> encFileNames;
	int cntToBeDecrypted = 0;
	int cntDecrypted = 0;

	for (const auto& entry : std::filesystem::recursive_directory_iterator(dir_in))
	{
		if (!entry.is_directory())
		{
			string ext = entry.path().filename().extension().string();
			if (ext.size() <= 1)
			{
				continue;
			}

			ext = ext.substr(1, ext.size() - 1);

			static std::regex rx("^[0-9]");             // Getting the regex object 
			std::smatch match;
			
			bool is_s57_ext = std::all_of(ext.begin(), ext.end(), ::isdigit);
			if (is_s57_ext)
			{
				//should be decrypted
				cntToBeDecrypted++;

				std::string p = entry.path().relative_path().string();
				std::string p_out = dir_out + "\\" + p;

				//check that the outpout dir exists
				std::filesystem::path p_check(p_out);
				std::filesystem::path dir = p_check.parent_path();
				if (std::filesystem::exists(dir) == false)
				{
					std::filesystem::create_directories(dir);
				}

				//delete existing file just in case
				if (std::filesystem::exists(p_out))
				{
					std::filesystem::remove(p_out);
				}

				//decrypt and create
				S63Error err = s63.decryptAndUnzipCell(entry.path().string(), p_out);

				if (err == S63Error::S63_ERR_OK)
				{
					++cntDecrypted;
					encFileNames.push_back(p);
				}
				else
				{
					int j = 0; //debug / log here for investigating decryption errors
				}
			}
			else
			{
				int j = 0; //debug / log here for looking into other files (not .000 .001 .002 etc)
			}
		}
		else
		{
			std::string p = entry.path().relative_path().string();
		}
	}

	//wipe empty generated dirs where decryption failed
	WipeEmptyDirs(dir_out);
	WriteFileWithENCnames(dir_out, encFileNames);

	//report
	std::cout << "-----------------------------" << std::endl;
	std::cout << "Decrypted:" << cntDecrypted << std::endl;
	std::cout << "-----------------------------" << std::endl;
	return 0;
}
