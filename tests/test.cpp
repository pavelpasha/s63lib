#include <cassert>

#include "blowfish.h"
#include "s63.h"
#include "simple_zip.h"
#include "utils.hpp"


using namespace std;
using namespace s63utils;
using namespace s63lib;
static void testBlowFish() {

    const string test_text = "This is a test clear data!!!!";

    CBlowFish bf("1234");
    const string encrypted = bf.encrypt(test_text);
    string decrypted = bf.decrypt(encrypted);

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


    std::vector<uint8_t> test_unzipped_data;
    std::string test_str = "This is a test unzipped data!!!!! 50 bytes length";
    test_unzipped_data.assign(test_str.begin(), test_str.end());

    SimpleZip zip;

    std::vector<uint8_t> zipped_data;
    bool OK = zip.zip("test.txt", test_unzipped_data, zipped_data);
    assert(OK);

    std::vector<uint8_t> unzipped;
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


    return 0;
}


