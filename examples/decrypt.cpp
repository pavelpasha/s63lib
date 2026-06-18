#include <iostream>
#include <cassert>
#include <filesystem>


#include "s63client.h"


using namespace std;
namespace fs = std::filesystem;
using namespace s63lib;

static void createDirectory(const std::string& path) {
    if (!fs::exists(path)) {
        if (fs::create_directory(path)) {
            std::cout << "Directory created: " << path << std::endl;
        } else {
            std::cerr << "Failed to create directory: " << path << std::endl;
        }
    } else {
        std::cout << "Directory already exists: " << path << std::endl;
    }
}

int main(int argc, char *argv[])
{

    string HW_ID = "12345";
    string M_KEY = "10121";
    string M_ID = "12";
    S63Client s63(HW_ID, M_KEY,M_ID);

    const auto test_cells_path = std::string(DATA_PATH);

    s63.importPermitFile(test_cells_path + "/PERMIT.TXT");

    const auto s63cell_path = test_cells_path + "/V01X01/ENC_ROOT/GB/GB40162A/9/0/GB40162A.000";
    const auto s57cell_path = "out/GB40162A.000";
    createDirectory("out");

    s63.decryptAndUnzipCell(s63cell_path, s57cell_path);



    return 0;
}


