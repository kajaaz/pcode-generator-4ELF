#include <cstdint>
#include <iostream>
#include <exception>
#include <vector>
#include <memory>
#include <sstream>
#include <iostream>
#include "sleigh.hh"
#include "loadimage.hh"
#include <LIEF/LIEF.hpp>
#include "generatepcode.hpp" 

using namespace std;
using namespace ghidra;

// Implementation of MyLoadImage
MyLoadImage::MyLoadImage(const std::string &elfFilePath) : LoadImage("elfLoader") {
    try {
        elfBinary = LIEF::ELF::Parser::parse(elfFilePath);
    } catch (const std::exception& e) {
        cerr << "Failed to load ELF file: " << e.what() << endl;
        elfBinary = nullptr;
    }
}

void MyLoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr) {
    uintb start = addr.getOffset();
    memset(ptr, 0, size); // Ensuring the memory is initially cleared

    if (!elfBinary) {
        cerr << "ELF binary not loaded." << endl;
        return;
    }

    for (const auto &segment : elfBinary->segments()) {
        uintb segmentStart = segment.virtual_address();
        uintb segmentEnd = segmentStart + segment.physical_size();
        
        if (start >= segmentStart && start < segmentEnd) {
            uintb offsetInSegment = start - segmentStart;
            int4 bytesToRead = min(size, static_cast<int4>(segmentEnd - start));
            
            auto content_span = segment.content(); 
            std::vector<uint8_t> data(content_span.begin(), content_span.end()); 

            if (offsetInSegment + bytesToRead <= data.size()) {
                memcpy(ptr, &data[offsetInSegment], bytesToRead);
            } else {
                cerr << "Error: Attempt to read beyond segment data." << endl;
            }
            return; // Data copied, exit the loop
        }
    }

    cerr << "Warning: Address 0x" << hex << start << " not found in any segment." << endl;
}


// Implementation of MyPcodeRawOut
void MyPcodeRawOut::dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) {
    if (outvar != nullptr) {
        print_vardata(pcodeStream, *outvar);
        pcodeStream << " = ";
    }
    pcodeStream << get_opname(opc);
    for (int4 i = 0; i < isize; ++i) {
        pcodeStream << ' ';
        print_vardata(pcodeStream, vars[i]);
    }
    pcodeStream << '\n';
}

// Implementation of MyPcodeDecoder
MyPcodeDecoder::MyPcodeDecoder(const string &specfile, const string &elfFilePath, uintb base_addr, uintb end_addr)
: loader(make_unique<MyLoadImage>(elfFilePath)), sleigh(loader.get(), &context) {
    DocumentStorage docstorage;
    Element *root = docstorage.openDocument(specfile)->getRoot();
    docstorage.registerTag(root);
    sleigh.initialize(docstorage);

    context.setVariableDefault("longMode", 1); //64-bit 
    context.setVariableDefault("addrsize", 2); //64-bit
    context.setVariableDefault("opsize", 2); //64-bit
}

std::string MyPcodeDecoder::decode_addr(uint64_t addr_in, uint64_t &instr_len) const {
    Address addr(sleigh.getDefaultCodeSpace(), addr_in);
    MyPcodeRawOut emit;

    // Log the address being decoded in hexadecimal format
    std::ostringstream logStream;
    logStream << "Attempting to decode address: 0x" << std::hex << addr_in;
    std::cout << logStream.str() << std::endl;

    try {
        instr_len = sleigh.oneInstruction(emit, addr);

        // Log successful decoding
        logStream.str(""); // Clear the stream
        logStream << "Successfully decoded instruction at address: 0x" << std::hex << addr_in
                  << " with length: " << std::dec << instr_len;
        std::cout << logStream.str() << std::endl;

        return emit.getPcode();
    } catch (const LowlevelError &e) {
        // Log the specific error and the address at which it occurred
        logStream.str(""); // Clear the stream
        logStream << "LowlevelError occurred during disassembly at address 0x"
                  << std::hex << addr_in << ": " << e.explain;
        std::cerr << logStream.str() << std::endl;

        return "Error: Disassembly failed due to LowlevelError.";
    } catch (const std::exception &e) {
        // Log the standard exception and the address
        logStream.str(""); // Clear the stream
        logStream << "Standard exception occurred during disassembly at address 0x"
                  << std::hex << addr_in << ": " << e.what();
        std::cerr << logStream.str() << std::endl;

        return "Error: Disassembly failed due to a standard exception.";
    } catch (...) {
        // Log an unknown error and the address
        logStream.str(""); // Clear the stream
        logStream << "Unknown exception occurred during disassembly at address 0x"
                  << std::hex << addr_in;
        std::cerr << logStream.str() << std::endl;

        return "Error: Disassembly failed due to an unknown error.";
    }
}

namespace ghidra {
    std::unique_ptr<MyPcodeDecoder> new_pcode_decoder(const std::string &specfile, const std::string &elfFilePath, uintb base_addr, uintb end_addr) {
        return std::make_unique<MyPcodeDecoder>(specfile, elfFilePath, base_addr, end_addr);
    }
}
