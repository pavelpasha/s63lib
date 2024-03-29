#include <iostream>
#include <fstream>
#include <cassert>

#include "blowfish.h"
#include "s63client.h"
#include "simple_zip.h"
#include "s63utils.hpp"


using namespace std;
using namespace hexutils;
static void testBlowFish() {

	string test_text = "This is a test clear data!!!!";

	CBlowFish bf("1234");
	string encrypted = bf.encryptConst(test_text);
	string decrypted = bf.decryptConst(encrypted);

	assert(test_text == decrypted);

}

static void testS63() {
	// All the test values is taken from S-63_e1.2.0_EN_Jan2015.pdf paper
	string test_hw_id = "12348";// 3132333438 (HEX)
	string test_m_key = "98765";// 3938373635 (HEX)
	string test_m_id = "01";	// 3031 (HEX)
	string test_userpermit = "73871727080876A07E450C043031";
	string test_ck1_hex = "C1CB518E9C"; // unprintanble in bytes
	string test_ck2_hex = "421571CC66"; // unprintanble in bytes
	string test_cellname = "NO4D0613";
	string test_expiry_date = "20000830";
	string test_cellpermit = "NO4D061320000830BEB9BFE3C7C6CE68B16411FD09F96982795C77B204F54D48";

	assert(S63::createUserPermit(test_m_key, test_hw_id, test_m_id) == test_userpermit);
	assert(S63::extractHwIdFromUserpermit(test_userpermit, test_m_key) == test_hw_id);

	assert(S63::createCellPermit(test_hw_id, hex_to_string(test_ck1_hex), hex_to_string(test_ck2_hex),
		test_cellname, test_expiry_date) == test_cellpermit);
	bool ok;
	auto cell_keys = S63::extractCellKeysFromCellpermit(test_cellpermit, test_hw_id, ok);
	assert(cell_keys.first == hex_to_string(test_ck1_hex));
	assert(cell_keys.second == hex_to_string(test_ck2_hex));

}

static void testZip() {

	
	string test_unzipped_data = "This is a test unzipped data!!!!! 50 bytes length";

	SimpleZip zip;

	string zipped_data;
	bool OK = zip.zip("test.txt", test_unzipped_data, zipped_data);
	assert(OK);

	string unzipped;
	OK = zip.unzip(zipped_data, unzipped);
	assert(OK);

	assert(test_unzipped_data == unzipped);


}


int main(int argc, char *argv[])
{
	
	testBlowFish();
	testZip();
	testS63();
	puts("All test passed!\n");


	//S63Client s63(HW_ID, "12345","12");
	//s63.importPermitFile("test_data\\PERMIT.txt");
	
	//return 0;
	//s63.installPermit("UA5T351920171130DA789B5FACF38036DA789B5FACF38036046BB7FB5CA8C749");
	//string baseCell = "UA5T3519";

	//for (const auto& entry : fs::recursive_directory_iterator("D:\\Maps\\s63\\ENC_ROOT\\UA\\" + baseCell)) {
	//	if (!entry.is_directory()) {
	//		string path = entry.path().string();
	//		string name = entry.path().filename().string();
	//		name = name.substr(0, name.find('.'));
	//		string ext = entry.path().filename().extension().string();
	//		if (name.find(baseCell) != string::npos)
	//			//decryptChart(decriptedCellKey, path, name, ext);
	//			s63.decryptAndUnzipCell(path, "decripted/" + name + "" + ext);
	//	}
	//}

	/*auto cell = s63.open("D:\\Maps\\s63\\ENC_ROOT\\UA\\UA5T3519\\3\\0\\UA5T3519.000");

	cout << cell.getSize() << endl;

	std::vector<char> buf(cell.getSize());

	int read = cell.read(buf.data(), cell.getSize());

	cout <<"read " << read << endl;

	read = cell.read(buf.data(), 1);

	cout << "read " << read << endl;*/


	return 0;
}


