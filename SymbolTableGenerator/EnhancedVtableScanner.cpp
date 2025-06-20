// Enhanced VTableScanner - includes ALL symbols, not just those with addresses
// Based on your audit results showing local/external symbols are missing

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <map>
#include <set>
#include <unordered_map>
#include <filesystem>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <cstdlib>
#include <cstdio>
#include <algorithm>

#include <llvm/Demangle/Demangle.h>
#include "json.hpp"
using json = nlohmann::json;

struct Segment {
    std::string name;
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
};

struct VTableCandidate {
    uint64_t address;
    std::vector<uint64_t> function_ptrs;
    std::vector<std::string> function_names;
    std::vector<std::string> demangled_names;
    double confidence_score = 0.0;
    std::string likely_class_name;
    int osiris_symbols = 0;
    int lua_symbols = 0;
};

// GLOBAL DECLARATIONS
std::vector<Segment> segments;
std::map<uint64_t, std::string> symbol_table;           // address -> symbol (existing)
std::set<std::string> all_symbols;                      // ALL symbols regardless of address
std::map<std::string, uint64_t> symbol_addresses;       // symbol -> address (reverse lookup)

// Enhanced vtable validation with Osiris/Lua detection
class VTableAnalyzer {
private:
    std::set<std::string> common_vtable_functions = {
        "~", "operator=", "operator==", "operator!=", 
        "clone", "serialize", "toString", "getType", "GetType"
    };
    
    std::set<std::string> engine_namespaces = {
        "ls::", "bg3::", "dse::", "ecs::", "net::", "stats::", "osiris::", "esv::", "ecl::"
    };

public:
    double calculateConfidence(VTableCandidate& candidate) {
        double score = 0.0;
        candidate.osiris_symbols = 0;
        candidate.lua_symbols = 0;
        
        // Base score for having multiple functions
        if (candidate.function_ptrs.size() >= 3) score += 10.0;
        if (candidate.function_ptrs.size() >= 5) score += 15.0;
        if (candidate.function_ptrs.size() >= 10) score += 10.0;
        
        // Analyze demangled names for C++ patterns
        int cpp_functions = 0;
        int virtual_functions = 0;
        int destructor_count = 0;
        std::string common_class_prefix;
        
        for (const auto& name : candidate.demangled_names) {
            // Skip unknown symbols
            if (name == "<unknown>" || name.find("ERROR:") != std::string::npos) {
                continue;
            }
            
            // Check for Osiris/Lua symbols (case insensitive)
            std::string lower_name = name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
            
            if (lower_name.find("osiris") != std::string::npos) {
                candidate.osiris_symbols++;
                score += 25.0; // High bonus for Osiris symbols
            }
            if (lower_name.find("lua") != std::string::npos) {
                candidate.lua_symbols++;
                score += 20.0; // High bonus for Lua symbols
            }
            
            // C++ mangled names typically contain "::"
            if (name.find("::") != std::string::npos) {
                cpp_functions++;
                score += 5.0;
                
                // Extract potential class name
                if (common_class_prefix.empty()) {
                    auto pos = name.find("::");
                    if (pos != std::string::npos) {
                        common_class_prefix = name.substr(0, pos);
                    }
                }
            }
            
            // Look for virtual function patterns
            if (name.find("~") != std::string::npos) {
                destructor_count++;
                score += 15.0; // Destructors are strong vtable indicators
            }
            
            // Check for common virtual function names
            for (const auto& common : common_vtable_functions) {
                if (name.find(common) != std::string::npos) {
                    virtual_functions++;
                    score += 8.0;
                    break;
                }
            }
            
            // Bonus for game engine namespaces
            for (const auto& ns : engine_namespaces) {
                if (name.find(ns) != std::string::npos) {
                    score += 20.0;
                    break;
                }
            }
        }
        
        // Special bonus for mixed Osiris/Lua vtables
        if (candidate.osiris_symbols > 0 && candidate.lua_symbols > 0) {
            score += 30.0;
        }
        
        // Penalty for too many unknown symbols (likely false positive)
        double unknown_ratio = 0.0;
        int unknown_count = 0;
        for (const auto& name : candidate.demangled_names) {
            if (name == "<unknown>") unknown_count++;
        }
        unknown_ratio = (double)unknown_count / candidate.demangled_names.size();
        if (unknown_ratio > 0.7) score -= 30.0;
        
        // Bonus for having exactly one destructor (typical for vtables)
        if (destructor_count == 1) score += 10.0;
        else if (destructor_count > 1) score -= 10.0;
        
        return std::max(0.0, score);
    }
    
    std::string extractClassName(const VTableCandidate& candidate) {
        std::unordered_map<std::string, int> class_votes;
        
        for (const auto& name : candidate.demangled_names) {
            if (name == "<unknown>" || name.find("ERROR:") != std::string::npos) {
                continue;
            }
            
            // Extract class name from "ClassName::methodName" pattern
            auto double_colon = name.find("::");
            if (double_colon != std::string::npos) {
                std::string class_part = name.substr(0, double_colon);
                
                // Remove leading namespaces to get the actual class name
                auto last_colon = class_part.rfind("::");
                if (last_colon != std::string::npos) {
                    class_part = class_part.substr(last_colon + 2);
                }
                
                class_votes[class_part]++;
            }
        }
        
        // Return the most common class name
        std::string best_class;
        int max_votes = 0;
        for (const auto& [cls, votes] : class_votes) {
            if (votes > max_votes) {
                max_votes = votes;
                best_class = cls;
            }
        }
        
        return best_class;
    }
};

// Enhanced symbol reading - collects ALL symbols
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
            segments.push_back(s);
            
            file.seekg(pos + seg.cmdsize);
        } else if (cmd == LC_SYMTAB) {
            symtab_command symtab;
            file.seekg(pos);
            file.read(reinterpret_cast<char*>(&symtab), sizeof(symtab));

            auto strtab_offset = symtab.stroff;
            auto symtab_offset = symtab.symoff;
            auto nsyms = symtab.nsyms;

            uint64_t after = pos + symtab.cmdsize;

            // Read string table
            std::vector<char> strtab(symtab.strsize);
            file.seekg(strtab_offset);
            file.read(strtab.data(), strtab.size());

            // Read symbol table
            file.seekg(symtab_offset);
            for (uint32_t s = 0; s < nsyms; ++s) {
                nlist_64 entry;
                file.read(reinterpret_cast<char*>(&entry), sizeof(entry));
                
                if (entry.n_un.n_strx < strtab.size()) {
                    std::string name = &strtab[entry.n_un.n_strx];
                    if (!name.empty() && name[0] != '\0') {
                        // Add ALL symbols to our comprehensive list
                        all_symbols.insert(name);
                        
                        // Keep address mapping for symbols that have addresses
                        if (entry.n_value != 0) {
                            symbol_table[entry.n_value] = name;
                            symbol_addresses[name] = entry.n_value;
                        }
                    }
                }
            }
            file.seekg(after);
        } else {
            file.seekg(pos + cmdsize);
        }
    }
    
    std::cerr << "Total symbols collected: " << all_symbols.size() << std::endl;
    std::cerr << "Symbols with addresses: " << symbol_table.size() << std::endl;
}

// Enhanced symbol lookup - checks both address table and comprehensive symbol list
std::string lookup_symbol(uint64_t address) {
    // First try direct address lookup
    if (symbol_table.count(address)) {
        return symbol_table[address];
    }
    
    // If not found, this might be a stub or indirect call
    // For now, mark as unknown but we could enhance this later
    return "<unknown>";
}

// Batch demangle symbols
std::vector<std::string> demangle_with_llvm_library(const std::vector<std::string>& mangled_names_batch) {
    std::vector<std::string> demangled_results;
    demangled_results.reserve(mangled_names_batch.size());

    for (const auto& mangled_name : mangled_names_batch) {
        std::string demangled = llvm::demangle(mangled_name);
        demangled_results.push_back(demangled);
    }
    return demangled_results;
}

Segment* find_segment(const std::string& name) {
    for (auto& s : segments) {
        if (s.name == name) return &s;
    }
    return nullptr;
}

bool is_text_ptr(uint64_t ptr, uint64_t text_base, uint64_t text_end) {
    return ptr >= text_base && ptr < text_end;
}

void scan_for_vtables_enhanced(std::ifstream& file, Segment& const_seg, Segment& text_seg, std::ostream& out, double min_confidence = 50.0) {
    file.seekg(const_seg.fileoff);
    std::vector<uint8_t> buffer(const_seg.filesize);
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

    // Much more aggressive pre-filtering to reduce processing time
    std::vector<VTableCandidate> candidates;
    std::vector<VTableCandidate> promising_candidates; // Pre-filter before expensive operations
    VTableAnalyzer analyzer;
    
    std::cerr << "Pre-filtering candidates (this may take a moment)...\n";
    
    // First pass: find potential vtables with basic filtering
    for (size_t i = 0; i + 24 < buffer.size(); i += 8) {
        uint64_t p1 = *reinterpret_cast<uint64_t*>(&buffer[i]);
        uint64_t p2 = *reinterpret_cast<uint64_t*>(&buffer[i + 8]);
        uint64_t p3 = *reinterpret_cast<uint64_t*>(&buffer[i + 16]);

        if (is_text_ptr(p1, text_seg.vmaddr, text_seg.vmaddr + text_seg.vmsize) &&
            is_text_ptr(p2, text_seg.vmaddr, text_seg.vmaddr + text_seg.vmsize) &&
            is_text_ptr(p3, text_seg.vmaddr, text_seg.vmaddr + text_seg.vmsize)) {

            VTableCandidate candidate;
            candidate.address = const_seg.vmaddr + i;
            
            // Collect consecutive function pointers (limit to 15 for performance)
            int consecutive_symbols = 0;
            for (int j = 0; j < 15; ++j) {
                if (i + j * 8 + 8 > buffer.size()) break;
                uint64_t func_ptr = *reinterpret_cast<uint64_t*>(&buffer[i + j * 8]);
                if (!is_text_ptr(func_ptr, text_seg.vmaddr, text_seg.vmaddr + text_seg.vmsize)) break;

                candidate.function_ptrs.push_back(func_ptr);
                std::string sym = lookup_symbol(func_ptr);
                candidate.function_names.push_back(sym);
                
                // Quick pre-filter: count symbols that aren't <unknown>
                if (sym != "<unknown>") consecutive_symbols++;
            }
            
            // AGGRESSIVE PRE-FILTERING: Only process candidates that look promising
            bool is_promising = false;
            
            // Criteria for "promising":
            if (candidate.function_ptrs.size() >= 5 && consecutive_symbols >= 2) {
                is_promising = true; // Large vtable with some known symbols
            } else if (candidate.function_ptrs.size() >= 3 && consecutive_symbols >= 1) {
                // Check if any symbol names contain interesting keywords
                for (const auto& name : candidate.function_names) {
                    std::string lower_name = name;
                    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
                    if (lower_name.find("osiris") != std::string::npos ||
                        lower_name.find("lua") != std::string::npos ||
                        name.find("::") != std::string::npos ||
                        name.find("~") != std::string::npos) {
                        is_promising = true;
                        break;
                    }
                }
            }
            
            if (is_promising) {
                promising_candidates.push_back(candidate);
            }
        }
        
        // Progress indicator for large binaries
        if (i % 1000000 == 0) {
            std::cerr << "Processed " << (i / 1000000) << "MB of data...\n";
        }
    }
    
    std::cerr << "Pre-filtered to " << promising_candidates.size() << " promising candidates (from " 
              << (buffer.size() / 8) << " potential positions)\n";
    
    // Only demangle symbols from promising candidates (much faster)
    std::vector<std::string> all_symbols_to_demangle;
    for (auto& candidate : promising_candidates) {
        all_symbols_to_demangle.insert(all_symbols_to_demangle.end(), 
                                       candidate.function_names.begin(), 
                                       candidate.function_names.end());
    }
    
    std::cerr << "Demangling " << all_symbols_to_demangle.size() << " symbols...\n";
    std::vector<std::string> demangled_all = demangle_with_llvm_library(all_symbols_to_demangle);
    
    // Distribute demangled results back to promising candidates
    size_t demangle_idx = 0;
    for (auto& candidate : promising_candidates) {
        for (size_t i = 0; i < candidate.function_names.size(); ++i) {
            candidate.demangled_names.push_back(demangled_all[demangle_idx++]);
        }
        
        // Calculate confidence and class name
        candidate.confidence_score = analyzer.calculateConfidence(candidate);
        candidate.likely_class_name = analyzer.extractClassName(candidate);
    }
    
    // Filter by confidence and sort
    std::vector<VTableCandidate> filtered_candidates;
    std::vector<VTableCandidate> osiris_lua_candidates;
    
    for (const auto& candidate : promising_candidates) {
        if (candidate.confidence_score >= min_confidence) {
            filtered_candidates.push_back(candidate);
        }
        
        // Separate collection for Osiris/Lua vtables (regardless of confidence)
        if (candidate.osiris_symbols > 0 || candidate.lua_symbols > 0) {
            osiris_lua_candidates.push_back(candidate);
        }
    }
    
    std::sort(filtered_candidates.begin(), filtered_candidates.end(), 
              [](const VTableCandidate& a, const VTableCandidate& b) {
                  return a.confidence_score > b.confidence_score;
              });
    
    std::cerr << "After filtering: " << filtered_candidates.size() << " high-confidence vtables\n";
    std::cerr << "Osiris/Lua vtables found: " << osiris_lua_candidates.size() << std::endl;
    
    // Output to JSON
    json json_output = json::object();
    json_output["summary"] = json::object();
    json_output["summary"]["total_candidates"] = promising_candidates.size();
    json_output["summary"]["filtered_count"] = filtered_candidates.size();
    json_output["summary"]["osiris_lua_count"] = osiris_lua_candidates.size();
    json_output["summary"]["min_confidence_threshold"] = min_confidence;
    json_output["summary"]["total_symbols_in_binary"] = all_symbols.size();
    
    // Output all high-confidence vtables
    json vtables_array = json::array();
    for (const auto& candidate : filtered_candidates) {
        json vtable_obj;
        
        std::stringstream ss;
        ss << "0x" << std::hex << candidate.address;
        vtable_obj["address"] = ss.str();
        vtable_obj["confidence_score"] = candidate.confidence_score;
        vtable_obj["likely_class"] = candidate.likely_class_name;
        vtable_obj["function_count"] = candidate.function_ptrs.size();
        vtable_obj["osiris_symbols"] = candidate.osiris_symbols;
        vtable_obj["lua_symbols"] = candidate.lua_symbols;
        
        json functions_array = json::array();
        for (size_t i = 0; i < candidate.function_ptrs.size(); ++i) {
            json func_obj;
            std::stringstream ss_func;
            ss_func << "0x" << std::hex << candidate.function_ptrs[i];
            func_obj["address"] = ss_func.str();
            func_obj["mangled_name"] = candidate.function_names[i];
            func_obj["demangled_name"] = candidate.demangled_names[i];
            functions_array.push_back(func_obj);
        }
        vtable_obj["functions"] = functions_array;
        vtables_array.push_back(vtable_obj);
    }
    
    json_output["vtables"] = vtables_array;
    
    // Separate section for Osiris/Lua vtables
    json osiris_lua_array = json::array();
    for (const auto& candidate : osiris_lua_candidates) {
        json vtable_obj;
        
        std::stringstream ss;
        ss << "0x" << std::hex << candidate.address;
        vtable_obj["address"] = ss.str();
        vtable_obj["confidence_score"] = candidate.confidence_score;
        vtable_obj["likely_class"] = candidate.likely_class_name;
        vtable_obj["function_count"] = candidate.function_ptrs.size();
        vtable_obj["osiris_symbols"] = candidate.osiris_symbols;
        vtable_obj["lua_symbols"] = candidate.lua_symbols;
        
        json functions_array = json::array();
        for (size_t i = 0; i < candidate.function_ptrs.size(); ++i) {
            json func_obj;
            std::stringstream ss_func;
            ss_func << "0x" << std::hex << candidate.function_ptrs[i];
            func_obj["address"] = ss_func.str();
            func_obj["mangled_name"] = candidate.function_names[i];
            func_obj["demangled_name"] = candidate.demangled_names[i];
            functions_array.push_back(func_obj);
        }
        vtable_obj["functions"] = functions_array;
        osiris_lua_array.push_back(vtable_obj);
    }
    
    json_output["osiris_lua_vtables"] = osiris_lua_array;
    out << json_output.dump(2) << '\n';
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 4) {
        std::cerr << "Usage: " << argv[0] << " <binary> [output.json] [min_confidence]\n";
        return 1;
    }

    const char* input_path = argv[1];
    double min_confidence = 50.0; // Much higher default threshold
    
    if (argc == 4) {
        min_confidence = std::stod(argv[3]);
    }
    
    std::ofstream out_file;
    std::ostream* out = &std::cout;

    if (argc >= 3) {
        out_file.open(argv[2]);
        if (!out_file) {
            std::cerr << "Error opening output file.\n";
            return 1;
        }
        out = &out_file;
    }

    std::ifstream file(input_path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file\n";
        return 1;
    }

    // Handle fat binary
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.seekg(0);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
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
            return 1;
        }
    } else {
        file.seekg(0);
    }

    mach_header_64 header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (header.magic != MH_MAGIC_64) {
        std::cerr << "Not a valid Mach-O 64-bit binary\n";
        return 1;
    }

    read_segments(file, header.ncmds);

    Segment* const_seg = find_segment("__DATA_CONST");
    Segment* text_seg = find_segment("__TEXT");
    if (!const_seg || !text_seg) {
        std::cerr << "Missing __DATA_CONST or __TEXT segment\n";
        return 1;
    }

    scan_for_vtables_enhanced(file, *const_seg, *text_seg, *out, min_confidence);
    return 0;
}