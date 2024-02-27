# pcode-generator-4ELF

### Dependencies

```
cd LIEF
mkdir build
cd build
cmake ..
make
cp include/LIEF/version.h include/LIEF/config.h ../include/LIEF
cp -r  include/LIEF/third-party/ ../include/LIEF
```

### Usage
```
g++ -std=c++17 -c src/generatepcode.cpp -o src/generatepcode.o -I./src -I./src/specfiles -I./ghidra/Ghidra/Features/Decompiler/src/decompile/cpp -I./LIEF/include -D__STDC_FORMAT_MACROS

g++ -std=c++17 -c src/main.cc -o src/main.o -I./src -I./src/specfiles -I./ghidra/Ghidra/Features/Decompiler/src/decompile/cpp -I./LIEF/include -D__STDC_FORMAT_MACROS

g++ -std=c++17 -o generate_pcode src/main.o src/generatepcode.o -L./LIEF/build -lLIEF -static ./ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/libdecomp.a -D__STDC_FORMAT_MACROS

./generate_pcode /path/to/bin
```