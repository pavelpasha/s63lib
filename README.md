# This is a IHO data protection scheme s63 implementation.
#
S63 charts actually the same as S57 is, but compressed with .zip and encrypted with a blowfish algorithm (It is not a different chart format). [This](https://github.com/pavelpasha/s63lib/blob/master/doc/S-63_e1.2.0_EN_Jan2015.pdf) paper describes how the s63 protection scheme works, please read it. 

In order to decrypt S63 cell (another words - convert it back to a plain S57), you need to know two things: a CELLPERMIT and HWID (A paper, i noticed below, explains what it is).
Lets assume you have it. There is the s63.h file In this repository, which declares a few usefull functions.
First of all you need to extract a cellkeys from a CELLPERMIT:

```c
static std::pair<std::string,std::string> extractCellKeysFromCellpermit(const std::string& cellpermit, const std::string& HW_ID, bool& ok);
```

You pass to it your CELLPERMIT and HWID and it returns you a pair of cellkeys.
With those cellkeys you can finally decpypt your s63 cell.

```c 
static S63Error decryptAndUnzipCellByKey(const std::string& in_path, const std::pair<std::string, std::string>& keys, const std::string& out_path);
```

First argument - path of your s63 cell; second - cellkeys; third - the path where your s57 cell you want to be saved.

For example:
```c
string example_hw_id = "12348";// 3132333438 (HEX)
string example_cellpermit = "NO4D061320000830BEB9BFE3C7C6CE68B16411FD09F96982795C77B204F54D48";
string s63_cell_path = "s63/NO4D06/NO4D06.000"
string output_cell_path = "s57/NO4D06/NO4D06.000"
bool ok;
auto cell_keys = S63::extractCellKeysFromCellpermit(example_cellpermit  example_hw_id , ok);
if(!ok) printf("error\n");
auto error = S63::decryptAndUnzipCellByKey(s63_cell_path, cell_keys, output_cell_path);
```

Basically, all the low-level functionality of this library is declared in the s63.h header.

The S63Client class is an example how it might be used in a user-side application, like a chartplotter.
```c
//Create an instance of the S63Client, witch is bounded to it`s HW_ID (Hardware id of this device), M_KEY (Manufactorer key) and M_ID (Manufactorer id) 
S63Client s63("HWID","MKEY","MID");
// Get an USERPERMIT for this device. And buy yoursef a some nice charts with this permit.
const auto userpermit = s63.getUserpermit();

// Once you have a charts, you probably wanna to decrypt it. To do that, insall CELLPERMITs (they will be saved in unordered_map [cellname --> cellpermit])
// cellpermits can be installed one by one, manually
string example_cellpermit = "NO4D061320000830BEB9BFE3C7C6CE68B16411FD09F96982795C77B204F54D48";
s63.installCellPermit(example_cellpermit);
// Or by importing all the cellpermits from a PERMITS.TXT file
s63.importPermitFile("/paths/to/PERMITS.TXT");

// If for gived s63 cell, a corresponding CELLPERMIT will be found among previously insalled, and all is valid, 
// you finally can get an decrypted chart cell as byte array, an do all you could to with a plain S57 cell.
std::string s57cell_decrypted = s63.open("/path/to/63cell/NO4D06/NO4D06.000");

// Or you can save it somewhere
const auto error = s63.decryptAndUnzipCell("/path/to/63cell/NO4D06/NO4D06.000","/path/to/decrypdedS57cell/NO4D06/NO4D06.000");
```
