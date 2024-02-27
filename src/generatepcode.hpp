#ifndef GENERATEPCODE_H
#define GENERATEPCODE_H

#include <cstdint>
#include <iostream>
#include <exception>
#include <vector>
#include <memory>
#include <sstream>
#include "sleigh.hh"
#include "loadimage.hh"
#include <LIEF/ELF.hpp> 

namespace ghidra {

// Additional utility function 
inline void print_vardata(std::ostream &s, const VarnodeData &data) {
    s << '(' << data.space->getName() << ',';
    data.space->printOffset(s, data.offset);
    s << ',' << std::dec << data.size << ')';
}

class MyLoadImage : public LoadImage {
    std::unique_ptr<LIEF::ELF::Binary> elfBinary;

public:
    MyLoadImage(const std::string &elfFilePath);
    virtual void loadFill(uint1 *ptr, int4 size, const Address &addr) override;
    virtual std::string getArchType() const override { return "x86-64"; } // Example implementation
    virtual void adjustVma(long int adjust) override {} // Minimal implementation
};

class MyPcodeRawOut : public PcodeEmit {
public:
    std::ostringstream pcodeStream;
    virtual void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) override;
    std::string getPcode() const { return pcodeStream.str(); }
};

class MyPcodeDecoder {
    std::unique_ptr<MyLoadImage> loader;
    ContextInternal context;
    Sleigh sleigh;

public:
    MyPcodeDecoder(const std::string &specfile, const std::string &elfFilePath, uintb base_addr, uintb end_addr);
    std::string decode_addr(uint64_t addr_in, uint64_t &instr_len) const;
};

std::unique_ptr<MyPcodeDecoder> new_pcode_decoder(const std::string &specfile, const std::string &elfFilePath, uintb base_addr, uintb end_addr);

} // namespace ghidra

#endif // GENERATEPCODE_H

