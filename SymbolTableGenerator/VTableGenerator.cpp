// BUILD VERSION - triggered by bg3se_macos.dylib (to be implemented)
// VTableScanner.cpp - Mach-O vtable extractor with fat binary support for game hooking

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <map>
#include <filesystem>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <cstdlib>
#include <cstdio>

// Include the LLVM Demangle header for in-process demangling
#include <llvm/Demangle/Demangle.h>

// Include the nlohmann/json header (assuming json.hpp is in your include path or same directory)
#include "json.hpp"
// For convenience, bring nlohmann::json into the current scope
using json = nlohmann::json;

// Uses installed Homebrew llvm's Demangle library to demangle
std::vector<std::string> demangle_with_llvm_library(const std::vector<std::string>& mangled_names_batch) {
    std::vector<std::string> demangled_results;
    demangled_results.reserve(mangled_names_batch.size()); // Pre-allocate to avoid reallocations

    for (const auto& mangled_name : mangled_names_batch) {
        // Use the llvm::demangle(std::string_view) function directly
        std::string demangled = llvm::demangle(mangled_name);
        demangled_results.push_back(demangled);
    }
    return demangled_results;
}

// Lay out skeleton for populating vtables
struct Segment {
    std::string name;
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
};

// GLOBAL DECLARATIONS - Ensure these are accessible to all functions
// The error "undeclared identifier 'segments'" indicates these were not in a global scope
std::vector<Segment> segments;
std::map<uint64_t, std::string> symbol_table; // Consider std::unordered_map for potentially faster lookups if not using `find_segment` heavily or order doesn't matter

void read_segments(std::ifstream& file, uint32_t ncmds) {
    for (uint32_t i = 0; i < ncmds; ++i) {
        uint64_t pos = file.tellg();
        uint32_t cmd, cmdsize;
        file.read(reinterpret_cast<char*>(&cmd), 4);
        file.read(reinterpret_cast<char*>(&cmdsize), 4);

        if (cmd == LC_SEGMENT_64) {
            file.seekg(pos);
            segment_command_64 seg{};
            file.read(reinterpret_cast<char*>(&seg), sizeof(seg));

            Segment s;
            s.name = std::string(reinterpret_cast<char*>(seg.segname), strnlen(reinterpret_cast<char*>(seg.segname), 16));
            s.vmaddr = seg.vmaddr;
            s.vmsize = seg.vmsize;
            s.fileoff = seg.fileoff;
            s.filesize = seg.filesize;
            segments.push_back(s); // 'segments' is now globally declared
            
            file.seekg(pos + seg.cmdsize);
        } else if (cmd == LC_SYMTAB) {
            symtab_command symtab;
            file.seekg(pos);
            file.read(reinterpret_cast<char*>(&symtab), sizeof(symtab));

            auto strtab_offset = symtab.stroff;
            auto symtab_offset = symtab.symoff;
            auto nsyms = symtab.nsyms;

            uint64_t after = pos + symtab.cmdsize;

            std::vector<char> strtab(symtab.strsize);
            file.seekg(strtab_offset);
            file.read(strtab.data(), strtab.size());

            file.seekg(symtab_offset);
            for (uint32_t s = 0; s < nsyms; ++s) {
                nlist_64 entry;
                file.read(reinterpret_cast<char*>(&entry), sizeof(entry));
                if (entry.n_value != 0 && entry.n_un.n_strx < strtab.size()) {
                    std::string name = &strtab[entry.n_un.n_strx];
                    symbol_table[entry.n_value] = name; // 'symbol_table' is now globally declared
                }
            }
            file.seekg(after);
        } else {
            file.seekg(pos + cmdsize);
        }
    }
}

Segment* find_segment(const std::string& name) {
    for (auto& s : segments) { // 'segments' is now globally declared
        if (s.name == name) return &s;
    }
    return nullptr;
}

bool is_text_ptr(uint64_t ptr, uint64_t text_base, uint64_t text_end) {
    return ptr >= text_base && ptr < text_end;
}

void scan_for_vtables(std::ifstream& file, Segment& const_seg, Segment& text_seg, std::ostream& out) {
    file.seekg(const_seg.fileoff);
    std::vector<uint8_t> buffer(const_seg.filesize);
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

    // Collect all mangled symbols found in vtables
    std::vector<std::string> symbols_to_demangle;
    // Store pairs of (vtable_addr, vector_index_of_func_ptr_in_symbols_to_demangle)
    // to map back after demangling
    std::vector<std::pair<uint64_t, std::vector<std::pair<uint64_t, size_t>>>> vtable_entries;
    
    // Temporary storage for current vtable's function pointers
    std::vector<std::pair<uint64_t, size_t>> current_vtable_func_ptrs;


    for (size_t i = 0; i + 24 < buffer.size(); i += 8) {
        
        uint64_t p1 = *reinterpret_cast<uint64_t*>(&buffer[i]);
        uint64_t p2 = *reinterpret_cast<uint64_t*>(&buffer[i + 8]);
        uint64_t p3 = *reinterpret_cast<uint64_t*>(&buffer[i + 16]);

        if (is_text_ptr(p1, text_seg.vmaddr, text_seg.vmaddr + text_seg.vmsize) &&
            is_text_ptr(p2, text_seg.vmaddr, text_seg.vmaddr + text_seg.vmsize) &&
            is_text_ptr(p3, text_seg.vmaddr, text_seg.vmaddr + text_seg.vmsize)) {

            uint64_t vtable_addr = const_seg.vmaddr + i;
            current_vtable_func_ptrs.clear(); // Reset for new vtable

            for (int j = 0; j < 10; ++j) { // Limit to 10 entries for brevity, adjust as needed
                if (i + j * 8 + 8 > buffer.size()) break;
                uint64_t func_ptr = *reinterpret_cast<uint64_t*>(&buffer[i + j * 8]);
                if (!is_text_ptr(func_ptr, text_seg.vmaddr, text_seg.vmaddr + text_seg.vmsize)) break;

                std::string sym = symbol_table.count(func_ptr) ? symbol_table[func_ptr] : "<unknown>";
                
                // Add to the batch for demangling
                size_t symbol_index = symbols_to_demangle.size();
                symbols_to_demangle.push_back(sym);
                current_vtable_func_ptrs.push_back({func_ptr, symbol_index});
            }
            if (!current_vtable_func_ptrs.empty()) {
                vtable_entries.push_back({vtable_addr, current_vtable_func_ptrs});
            }
        }
    }

    // Demangle all collected symbols in a single batch call using the LLVM library
    std::vector<std::string> demangled_symbols = demangle_with_llvm_library(symbols_to_demangle);

    // Now, iterate through the vtable entries and print them with demangled names
    for (const auto& vtable_entry : vtable_entries) {
        out << "[VTable] 0x" << std::hex << vtable_entry.first << ":\n"; // Vtable address
        for (const auto& func_ptr_info : vtable_entry.second) {
            uint64_t func_ptr = func_ptr_info.first;
            size_t demangled_index = func_ptr_info.second;
            
            std::string demangled_name = "<demangle_error>"; // Default error
            if (demangled_index < demangled_symbols.size()) {
                demangled_name = demangled_symbols[demangled_index];
            } else {
                // This case should ideally not happen if demangle_with_llvm_library returns consistent size
                demangled_name = "ERROR: Missing demangled symbol";
            }
            
            out << "  - 0x" << std::hex << func_ptr << ": " << demangled_name << "\n";
        }
    }
}


// This is your new entry point function for the VTableScanner logic
// It should be callable from your hooking code.
// Consider using a boolean return value to indicate success/failure.
// Use const char* for paths if your hooking framework prefers C-style strings.
extern "C" void __attribute__((visibility("default"))) InitializeVTableScanner(const char* game_binary_path, const char* output_json_path) {
    // Replicate the setup logic from the original main function here
    // This function will be called by your hook or library initializer

    std::string input_path_str(game_binary_path);
    std::ofstream out_file;
    std::ostream* out = &std::cout; // Default to stdout if no output_json_path

    if (output_json_path && strlen(output_json_path) > 0) {
        out_file.open(output_json_path);
        if (!out_file) {
            std::cerr << "Error opening output file: " << output_json_path << "\n";
            // In a real hooking scenario, you might log this error elsewhere,
            // or use a different error reporting mechanism.
            return; // Indicate failure
        }
        out = &out_file;
    } else {
        std::cerr << "VTableScanner: No output JSON path provided. Output will go to stdout/stderr.\n";
    }

    std::ifstream file(input_path_str, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open game binary: " << game_binary_path << "\n";
        return; // Indicate failure
    }

    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.seekg(0);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        // ... (your existing fat binary handling logic) ...
        fat_header fh;
        file.read(reinterpret_cast<char*>(&fh), sizeof(fh));
        uint32_t nfat_arch = (magic == FAT_CIGAM) ? __builtin_bswap32(fh.nfat_arch) : fh.nfat_arch;

        bool found_arm64 = false;
        for (uint32_t i = 0; i < nfat_arch; ++i) {
            fat_arch arch;
            file.read(reinterpret_cast<char*>(&arch), sizeof(arch));
            uint32_t cputype = (magic == FAT_CIGAM) ? __builtin_bswap32(arch.cputype) : arch.cputype;
            uint32_t offset = (magic == FAT_CIGAM) ? __builtin_bswap32(arch.offset) : arch.offset;

            if (cputype == CPU_TYPE_ARM64) {
                file.seekg(offset);
                file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
                if (magic == MH_MAGIC_64) {
                    file.seekg(offset);
                    found_arm64 = true;
                    break;
                }
            }
        }

        if (!found_arm64) {
            std::cerr << "ARM64 slice not found in fat binary.\n";
            return; // Indicate failure
        }
    } else {
        file.seekg(0);
    }

    mach_header_64 header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (header.magic != MH_MAGIC_64) {
        std::cerr << "Not a valid Mach-O 64-bit binary\n";
        return; // Indicate failure
    }

    // Reset global state for segments and symbol_table each time,
    // as this function might be called multiple times in some testing scenarios,
    // or to ensure clean state if the library is loaded/unloaded/reloaded.
    segments.clear();
    symbol_table.clear();

    read_segments(file, header.ncmds);

    std::cerr << "Discovered segments:\n";
    for (const auto& seg : segments) {
        std::cerr << " - " << seg.name << "\n";
    }

    Segment* const_seg = find_segment("__DATA_CONST");
    Segment* text_seg = find_segment("__TEXT");
    if (!const_seg || !text_seg) {
        std::cerr << "Missing __DATA_CONST or __TEXT segment\n";
        return; // Indicate failure
    }

    // Call the core scanning logic
    scan_for_vtables(file, *const_seg, *text_seg, *out);

    // No return needed if void, or return success code
}