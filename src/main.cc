#include <fstream>
#include <iostream>
#include <filesystem>
#include "generatepcode.hpp"

using namespace std;
using namespace ghidra;
namespace fs = std::filesystem;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <ELF_FILE_PATH>" << endl;
        return 1;
    }

    const string specfile = "src/specfiles/x86-64.sla";
    const string elfFilePath = argv[1];
    const fs::path elfPath(elfFilePath);
    string outputFileName = "output_" + elfPath.filename().string() + ".txt";

    uintb base_addr = 0x400000; // Start of the LOAD segment with executable code
    uintb end_addr = base_addr + 0x8ffd9; // End of the segment

    auto decoder = new_pcode_decoder(specfile, elfFilePath, base_addr, end_addr);

    ofstream out(outputFileName);
    if (!out.is_open()) {
        cerr << "Failed to open output file: " << outputFileName << endl;
        return 2;
    }

    uint64_t addr = base_addr;
    uint64_t instr_len = 0;
    while (addr < end_addr) {
        string pcode = decoder->decode_addr(addr, instr_len);
        if (pcode.empty() || instr_len == 0) break; // End of file or error

        out << "Address: " << hex << addr << '\n';
        out << pcode << '\n';

        addr += instr_len;
    }

    cout << "P-code output to: " << outputFileName << endl;

    return 0;
}

