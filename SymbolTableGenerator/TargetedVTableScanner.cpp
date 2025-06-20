// TargetedVTableScanner.cpp - Only extracts the essential symbols you've identified
// Based on your reverse engineering work and log analysis

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <sstream>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include "json.hpp"

using json = nlohmann::json;

// Essential symbols identified from your analysis
struct EssentialSymbol {
    std::string name;
    uint64_t address;
    std::string category;
    bool critical;
};

class TargetedSymbolExtractor {
private:
    // Known essential symbols from your bg3se_symbol_finder_out.txt
    std::vector<EssentialSymbol> essential_symbols = {
        // Core Osiris hooks (CRITICAL for bg3se)
        {"esv::OsirisAutomatedDialogTask", 0x1088c2d08, "osiris_core", true},
        {"esv::OsirisAutomatedDialogTask::Update", 0x1088c2d08, "osiris_core", true},
        {"esv::OsirisAutomatedDialogTask::SavegameVisit", 0x1088c2d10, "osiris_core", true},
        
        // Core game managers
        {"ls::GlobalAllocator", 0x1088aa118, "memory", true},
        {"ecs::EntityWorld::Update", 0x10849b950, "ecs", true},
        {"ecl::EoCClient", 0x108837970, "client", true},
        {"esv::EoCServer", 0x1088b2508, "server", true},
        
        // String and file systems
        {"ls::FixedString", 0x10890a460, "strings", true},
        {"ls::FileReader", 0x10890aba8, "io", false},
        
        // State machines
        {"ecl::GameStateMachine::Update", 0x108730f40, "state", true},
        {"esv::GameStateMachine::Update", 0x1088d07d0, "state", true},
        
        // Localization and saves
        {"ls::gTranslatedStringRepository", 0x1088a3b38, "localization", false},
        {"esv::SavegameManager", 0x10882b988, "saves", true},
        
        // Stats system
        {"eoc::PassivePrototype::Init", 0x108729b90, "stats", false},
    };
    
    // Lua bridge function patterns from your lua_bridge_out.txt
    std::vector<std::string> lua_bridge_patterns = {
        "ls::khonsu::CallApi::CallFunction",
        "ls::thoth::client::condition",
        "ls::thoth::client::action",
        "_Function_CanMove_",
        "_Function_Surface_",
        "_Function_Character_",
        "_Function_HasStatus_",
        "_Function_IsInCombat_",
    };
    
    std::unordered_map<uint64_t, std::string> symbol_table;
    std::unordered_map<std::string, uint64_t> reverse_lookup;
    
public:
    struct PatternSearchResult {
        std::vector<SymbolPattern> found_patterns;
        std::vector<std::string> missing_patterns;
        int total_symbols_scanned = 0;
    };
    
    PatternSearchResult searchSymbolPatterns(const std::string& binary_path) {
        PatternSearchResult result;
        
        std::ifstream file(binary_path, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open binary: " << binary_path << std::endl;
            return result;
        }
        
        // Handle fat binary (if needed)
        if (!seekToArm64Slice(file)) {
            std::cerr << "Failed to find ARM64 slice" << std::endl;
            return result;
        }
        
        // Read Mach-O header
        mach_header_64 header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        if (header.magic != MH_MAGIC_64) {
            std::cerr << "Not a valid Mach-O 64-bit binary" << std::endl;
            return result;
        }
        
        // Extract all symbols and strings
        extractAllData(file, header.ncmds, result);
        
        // Search for each pattern
        findSymbolsByPatterns(result);
        
        return result;
    }
    
    void exportToHeaderFile(const PatternSearchResult& result, const std::string& output_path) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Failed to create output file: " << output_path << std::endl;
            return;
        }
        
        out << "#pragma once\n";
        out << "// Auto-generated bg3se macOS symbol definitions\n";
        out << "// Generated from runtime pattern search\n\n";
        out << "#include <cstdint>\n\n";
        out << "namespace bg3se::macos {\n\n";
        
        // Critical symbols section
        out << "// CRITICAL SYMBOLS - Required for bg3se functionality\n";
        out << "namespace critical {\n";
        for (const auto& pattern : result.found_patterns) {
            if (pattern.critical && pattern.found_address != 0) {
                std::string safe_name = makeSafeName(pattern.name);
                out << "    constexpr uintptr_t " << safe_name << " = 0x" 
                    << std::hex << pattern.found_address << "; // " << pattern.name << "\n";
            }
        }
        out << "}\n\n";
        
        // Optional symbols section
        out << "// OPTIONAL SYMBOLS - Nice to have but not critical\n";
        out << "namespace optional {\n";
        for (const auto& pattern : result.found_patterns) {
            if (!pattern.critical && pattern.found_address != 0) {
                std::string safe_name = makeSafeName(pattern.name);
                out << "    constexpr uintptr_t " << safe_name << " = 0x" 
                    << std::hex << pattern.found_address << "; // " << pattern.name << "\n";
            }
        }
        out << "}\n\n";
        
        out << "} // namespace bg3se::macos\n";
        out.close();
        
        std::cout << "✅ Exported " << result.found_patterns.size() << " symbol patterns to " << output_path << std::endl;
    }
    
    void exportToBinaryMappings(const ExtractionResult& result, const std::string& output_path) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Failed to create mappings file: " << output_path << std::endl;
            return;
        }
        
        out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        out << "<BinaryMappings>\n";
        out << "  <Mappings Version=\"4.47.63.76\" Platform=\"MacOS\" Default=\"true\">\n";
        out << "    <!-- Auto-generated macOS binary mappings for bg3se -->\n";
        out << "    <!-- Based on reverse engineering analysis from your logs -->\n\n";
        
        // System library imports for macOS
        out << "    <DllImport Module=\"libSystem.B.dylib\" Proc=\"open\" Symbol=\"libc_open\" />\n";
        out << "    <DllImport Module=\"libSystem.B.dylib\" Proc=\"close\" Symbol=\"libc_close\" />\n";
        out << "    <DllImport Module=\"libSystem.B.dylib\" Proc=\"read\" Symbol=\"libc_read\" />\n";
        out << "    <DllImport Module=\"libSystem.B.dylib\" Proc=\"write\" Symbol=\"libc_write\" />\n\n";
        
        // Critical symbols from your analysis
        for (const auto& symbol : result.found_symbols) {
            if (symbol.critical) {
                std::string mapping_name = makeSafeMappingName(symbol.name);
                out << "    <Mapping Name=\"" << mapping_name << "\" Critical=\"true\">\n";
                out << "      <Target Type=\"Absolute\" Offset=\"0x" << std::hex << symbol.address 
                    << "\" Symbol=\"" << mapping_name << "\" />\n";
                out << "    </Mapping>\n\n";
            }
        }
        
    void exportToBinaryMappings(const PatternSearchResult& result, const std::string& output_path) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Failed to create mappings file: " << output_path << std::endl;
            return;
        }
        
        out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        out << "<BinaryMappings>\n";
        out << "  <Mappings Version=\"4.47.63.76\" Platform=\"MacOS\" Default=\"true\">\n";
        out << "    <!-- Auto-generated macOS binary mappings for bg3se -->\n";
        out << "    <!-- Based on runtime pattern search -->\n\n";
        
        // System library imports for macOS
        out << "    <DllImport Module=\"libSystem.B.dylib\" Proc=\"open\" Symbol=\"libc_open\" />\n";
        out << "    <DllImport Module=\"libSystem.B.dylib\" Proc=\"close\" Symbol=\"libc_close\" />\n";
        out << "    <DllImport Module=\"libSystem.B.dylib\" Proc=\"read\" Symbol=\"libc_read\" />\n";
        out << "    <DllImport Module=\"libSystem.B.dylib\" Proc=\"write\" Symbol=\"libc_write\" />\n\n";
        
        // Group patterns by category for better organization
        std::unordered_map<std::string, std::vector<const SymbolPattern*>> categorized_patterns;
        for (const auto& pattern : result.found_patterns) {
            if (pattern.found_address != 0) {
                categorized_patterns[pattern.category].push_back(&pattern);
            }
        }
        
        // Output patterns by category
        for (const auto& [category, patterns] : categorized_patterns) {
            out << "    <!-- " << category << " symbols -->\n";
            
            for (const auto* pattern : patterns) {
                std::string mapping_name = makeSafeMappingName(pattern->name);
                out << "    <Mapping Name=\"" << mapping_name << "\" Critical=\"" 
                    << (pattern->critical ? "true" : "false") << "\">\n";
                out << "      <Target Type=\"Absolute\" Offset=\"0x" << std::hex << pattern->found_address 
                    << "\" Symbol=\"" << mapping_name << "\" />\n";
                out << "    </Mapping>\n\n";
            }
        }
        
        out << "  </Mappings>\n";
        out << "</BinaryMappings>\n";
        out.close();
        
        std::cout << "✅ Exported BG3SE-compatible binary mappings to " << output_path << std::endl;
    }

private:
    void extractAllData(std::ifstream& file, uint32_t ncmds, PatternSearchResult& result) {
        // Extract symbol table AND string table for pattern matching
        for (uint32_t i = 0; i < ncmds; ++i) {
            uint64_t pos = file.tellg();
            uint32_t cmd, cmdsize;
            file.read(reinterpret_cast<char*>(&cmd), 4);
            file.read(reinterpret_cast<char*>(&cmdsize), 4);
            
            if (cmd == LC_SYMTAB) {
                extractSymbolTable(file, pos, result);
            } else if (cmd == LC_SEGMENT_64) {
                extractStringLiterals(file, pos, result);
            }
            
            file.seekg(pos + cmdsize);
        }
    }
    
    void extractSymbolTable(std::ifstream& file, uint64_t cmd_pos, PatternSearchResult& result) {
        symtab_command symtab;
        file.seekg(cmd_pos);
        file.read(reinterpret_cast<char*>(&symtab), sizeof(symtab));
        
        // Read string table
        std::vector<char> strtab(symtab.strsize);
        file.seekg(symtab.stroff);
        file.read(strtab.data(), strtab.size());
        
        // Read symbol entries
        file.seekg(symtab.symoff);
        for (uint32_t s = 0; s < symtab.nsyms; ++s) {
            nlist_64 entry;
            file.read(reinterpret_cast<char*>(&entry), sizeof(entry));
            
            if (entry.n_un.n_strx < strtab.size() && entry.n_value != 0) {
                std::string name = &strtab[entry.n_un.n_strx];
                if (!name.empty()) {
                    symbol_table[entry.n_value] = name;
                    reverse_lookup[name] = entry.n_value;
                    result.total_symbols_scanned++;
                }
            }
        }
    }
    
    void extractStringLiterals(std::ifstream& file, uint64_t cmd_pos, PatternSearchResult& result) {
        // Parse segment and look for string sections like __cstring
        segment_command_64 seg;
        file.seekg(cmd_pos);
        file.read(reinterpret_cast<char*>(&seg), sizeof(seg));
        
        // Look for __cstring section
        uint64_t section_offset = cmd_pos + sizeof(segment_command_64);
        for (uint32_t i = 0; i < seg.nsects; ++i) {
            section_64 sect;
            file.seekg(section_offset + i * sizeof(section_64));
            file.read(reinterpret_cast<char*>(&sect), sizeof(sect));
            
            std::string sectname(reinterpret_cast<char*>(sect.sectname), 
                               strnlen(reinterpret_cast<char*>(sect.sectname), 16));
            
            if (sectname == "__cstring") {
                extractStringsFromSection(file, sect, result);
                break;
            }
        }
    }
    
    void extractStringsFromSection(std::ifstream& file, const section_64& sect, PatternSearchResult& result) {
        file.seekg(sect.offset);
        std::vector<char> string_data(sect.size);
        file.read(string_data.data(), string_data.size());
        
        // Parse null-terminated strings
        std::string current_string;
        uint64_t string_offset = 0;
        
        for (uint64_t i = 0; i < sect.size; ++i) {
            if (string_data[i] == '\0') {
                if (!current_string.empty()) {
                    uint64_t string_addr = sect.addr + string_offset;
                    string_table[current_string] = string_addr;
                    current_string.clear();
                }
                string_offset = i + 1;
            } else {
                current_string += string_data[i];
            }
        }
    }
    
    void findSymbolsByPatterns(PatternSearchResult& result) {
        std::cout << "🔍 Searching for symbols using patterns...\n";
        
        for (auto& pattern : symbol_patterns) {
            bool found = false;
            
            // Search by string patterns first (most reliable)
            for (const auto& string_pattern : pattern.string_patterns) {
                auto string_addr = findStringLiteral(string_pattern);
                if (string_addr != 0) {
                    // Found the string, now find nearby code that references it
                    auto symbol_addr = findCodeReferencingString(string_addr, pattern.name);
                    if (symbol_addr != 0) {
                        pattern.found_address = symbol_addr;
                        result.found_patterns.push_back(pattern);
                        found = true;
                        std::cout << "   ✅ Found " << pattern.name << " at 0x" << std::hex << symbol_addr 
                                  << " (via string: \"" << string_pattern << "\")\n";
                        break;
                    }
                }
            }
            
            // Fallback to symbol name matching
            if (!found) {
                for (const auto& [addr, symbol_name] : symbol_table) {
                    if (symbol_name.find(pattern.name) != std::string::npos) {
                        pattern.found_address = addr;
                        result.found_patterns.push_back(pattern);
                        found = true;
                        std::cout << "   ✅ Found " << pattern.name << " at 0x" << std::hex << addr 
                                  << " (via symbol matching)\n";
                        break;
                    }
                }
            }
            
            if (!found) {
                result.missing_patterns.push_back(pattern.name);
                std::cout << "   ❌ Could not find " << pattern.name << "\n";
            }
        }
    }
    
    uint64_t findStringLiteral(const std::string& target) {
        auto it = string_table.find(target);
        return (it != string_table.end()) ? it->second : 0;
    }
    
    uint64_t findCodeReferencingString(uint64_t string_addr, const std::string& symbol_name) {
        // This is a simplified implementation
        // In a real implementation, you'd disassemble and look for references to string_addr
        // For now, we'll try to find symbols that might be related
        
        // Look for symbols with similar names near the string
        for (const auto& [addr, name] : symbol_table) {
            if (name.find(symbol_name.substr(0, 10)) != std::string::npos) {
                // Very rough heuristic: if symbol is within 1MB of string, consider it a match
                if (std::abs(static_cast<int64_t>(addr) - static_cast<int64_t>(string_addr)) < 0x100000) {
                    return addr;
                }
            }
        }
        
        return 0;
    }n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"App__LoadGraphicSettings\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"App__Ctor\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"App__Ctor\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- Osiris Integration Points -->\n";
        out << "    <Mapping Name=\"esv__OsirisAutomatedDialogTask\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x1088c2d08\" Symbol=\"esv__OsirisAutomatedDialogTask\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"esv__OsirisAutomatedDialogTask__Update\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x1088c2d08\" Symbol=\"esv__OsirisAutomatedDialogTask__Update\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"esv__OsirisAutomatedDialogTask__SavegameVisit\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x1088c2d10\" Symbol=\"esv__OsirisAutomatedDialogTask__SavegameVisit\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"esv__OsirisVariableHelper__SavegameVisit\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"esv__OsirisVariableHelper__SavegameVisit\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- Core Game Managers -->\n";
        out << "    <Mapping Name=\"ls__GlobalAllocator\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x1088aa118\" Symbol=\"ls__GlobalAllocator\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__GlobalAllocator__Get\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__GlobalAllocator__Get\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__GlobalAllocator__Free\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__GlobalAllocator__Free\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__GlobalAllocator__Alloc\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__GlobalAllocator__Alloc\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- ECS System -->\n";
        out << "    <Mapping Name=\"ecs__EntityWorld__Update\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x10849b950\" Symbol=\"ecs__EntityWorld__Update\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ecs__EntityWorld__FlushECBs\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ecs__EntityWorld__FlushECBs\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- Client/Server -->\n";
        out << "    <Mapping Name=\"ecl__EoCClient\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x108837970\" Symbol=\"ecl__EoCClient\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"esv__EoCServer\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x1088b2508\" Symbol=\"esv__EoCServer\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ecl__GameStateThreaded__GameStateWorker__DoWork\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ecl__GameStateThreaded__GameStateWorker__DoWork\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"esv__GameStateThreaded__GameStateWorker__DoWork\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"esv__GameStateThreaded__GameStateWorker__DoWork\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- String and File Systems -->\n";
        out << "    <Mapping Name=\"ls__FixedString\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x10890a460\" Symbol=\"ls__FixedString\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__FixedString__IncRef\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__FixedString__IncRef\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__FixedString__GetString\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__FixedString__GetString\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__FixedString__CreateFromString\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__FixedString__CreateFromString\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__gGlobalStringTable\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__gGlobalStringTable\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__FileReader__ctor\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__FileReader__ctor\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__FileReader__dtor\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__FileReader__dtor\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ls__PathRoots\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__PathRoots\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- State Machines -->\n";
        out << "    <Mapping Name=\"ecl__GameStateMachine__Update\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x108730f40\" Symbol=\"ecl__GameStateMachine__Update\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"esv__GameStateMachine__Update\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x1088d07d0\" Symbol=\"esv__GameStateMachine__Update\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ecl__gGameStateEventManager\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ecl__gGameStateEventManager\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"esv__gGameStateEventManager\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"esv__gGameStateEventManager\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- Stats System (Critical for Modding) -->\n";
        out << "    <Mapping Name=\"RPGStats__Load\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"RPGStats__Load\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"RPGStats__PreParseDataFolder\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"RPGStats__PreParseDataFolder\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"gRPGStats\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"gRPGStats\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"eoc__PassivePrototype__Init\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x108729b90\" Symbol=\"eoc__PassivePrototype__Init\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"stats__Object__SetPropertyString\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"stats__Object__SetPropertyString\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- Resource Management -->\n";
        out << "    <Mapping Name=\"ls__gGlobalResourceManager\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ls__gGlobalResourceManager\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"eoc__gResourceManager\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"eoc__gResourceManager\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- Level Management -->\n";
        out << "    <Mapping Name=\"esv__LevelManager\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"esv__LevelManager\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"ecl__LevelManager\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x0\" Symbol=\"ecl__LevelManager\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- Save and Localization -->\n";
        out << "    <Mapping Name=\"ls__gTranslatedStringRepository\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x1088a3b38\" Symbol=\"ls__gTranslatedStringRepository\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <Mapping Name=\"esv__SavegameManager\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x10882b988\" Symbol=\"esv__SavegameManager\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "    <!-- Stats System -->\n";
        out << "    <Mapping Name=\"eoc__PassivePrototype__Init\" Critical=\"true\">\n";
        out << "      <Target Type=\"Absolute\" Offset=\"0x108729b90\" Symbol=\"eoc__PassivePrototype__Init\" />\n";
        out << "    </Mapping>\n\n";
        
        out << "  </Mappings>\n";
        out << "</BinaryMappings>\n";
        out.close();
        
        std::cout << "✅ Exported BG3SE-compatible binary mappings to " << output_path << std::endl;
    }

private:
    bool seekToArm64Slice(std::ifstream& file) {
        uint32_t magic = 0;
        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        file.seekg(0);
        
        if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
            fat_header fh;
            file.read(reinterpret_cast<char*>(&fh), sizeof(fh));
            uint32_t nfat_arch = (magic == FAT_CIGAM) ? __builtin_bswap32(fh.nfat_arch) : fh.nfat_arch;
            
            for (uint32_t i = 0; i < nfat_arch; ++i) {
                fat_arch arch;
                file.read(reinterpret_cast<char*>(&arch), sizeof(arch));
                uint32_t cputype = (magic == FAT_CIGAM) ? __builtin_bswap32(arch.cputype) : arch.cputype;
                uint32_t offset = (magic == FAT_CIGAM) ? __builtin_bswap32(arch.offset) : arch.offset;
                
                if (cputype == CPU_TYPE_ARM64) {
                    file.seekg(offset);
                    return true;
                }
            }
            return false;
        }
        
        return true; // Single architecture binary
    }
    
    void extractSymbolTable(std::ifstream& file, uint32_t ncmds, ExtractionResult& result) {
        for (uint32_t i = 0; i < ncmds; ++i) {
            uint64_t pos = file.tellg();
            uint32_t cmd, cmdsize;
            file.read(reinterpret_cast<char*>(&cmd), 4);
            file.read(reinterpret_cast<char*>(&cmdsize), 4);
            
            if (cmd == LC_SYMTAB) {
                symtab_command symtab;
                file.seekg(pos);
                file.read(reinterpret_cast<char*>(&symtab), sizeof(symtab));
                
                // Read string table
                std::vector<char> strtab(symtab.strsize);
                file.seekg(symtab.stroff);
                file.read(strtab.data(), strtab.size());
                
                // Read symbol entries
                file.seekg(symtab.symoff);
                for (uint32_t s = 0; s < symtab.nsyms; ++s) {
                    nlist_64 entry;
                    file.read(reinterpret_cast<char*>(&entry), sizeof(entry));
                    
                    if (entry.n_un.n_strx < strtab.size() && entry.n_value != 0) {
                        std::string name = &strtab[entry.n_un.n_strx];
                        if (!name.empty()) {
                            symbol_table[entry.n_value] = name;
                            reverse_lookup[name] = entry.n_value;
                            result.total_symbols_scanned++;
                        }
                    }
                }
                
                file.seekg(pos + symtab.cmdsize);
            } else {
                file.seekg(pos + cmdsize);
            }
        }
    }
    
    void findEssentialSymbols(ExtractionResult& result) {
        for (auto& essential : essential_symbols) {
            bool found = false;
            
            // Try exact address match first
            if (symbol_table.count(essential.address)) {
                essential.name = symbol_table[essential.address]; // Update with actual name
                result.found_symbols.push_back(essential);
                found = true;
            } else {
                // Try pattern matching in symbol names
                for (const auto& [addr, name] : symbol_table) {
                    if (name.find(essential.name.substr(0, 20)) != std::string::npos) {
                        essential.address = addr;
                        essential.name = name;
                        result.found_symbols.push_back(essential);
                        found = true;
                        break;
                    }
                }
            }
            
            if (!found) {
                result.missing_symbols.push_back(essential.name);
            }
        }
    }
    
    void findLuaBridgeFunctions(ExtractionResult& result) {
        for (const auto& [addr, name] : symbol_table) {
            for (const auto& pattern : lua_bridge_patterns) {
                if (name.find(pattern) != std::string::npos) {
                    result.found_lua_bridges.push_back(name);
                    break;
                }
            }
        }
    }
    
    std::string makeSafeName(const std::string& name) {
        std::string safe = name;
        // Replace problematic characters
        for (char& c : safe) {
            if (!std::isalnum(c)) c = '_';
        }
        // Remove double underscores
        size_t pos = 0;
        while ((pos = safe.find("__", pos)) != std::string::npos) {
            safe.replace(pos, 2, "_");
        }
        return safe;
    }
    
    std::string makeSafeMappingName(const std::string& name) {
        std::string safe = name;
        // Replace :: with __
        size_t pos = 0;
        while ((pos = safe.find("::", pos)) != std::string::npos) {
            safe.replace(pos, 2, "__");
            pos += 2;
        }
        return safe;
    }
};

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <bg3_binary> [output_header] [output_mappings]\n";
        return 1;
    }
    
    std::string binary_path = argv[1];
    std::string header_path = argc > 2 ? argv[2] : "bg3se_macos_symbols.h";
    std::string mappings_path = argc > 3 ? argv[3] : "bg3se_macos_mappings.xml";
    
    TargetedSymbolExtractor extractor;
    auto result = extractor.extractTargetedSymbols(binary_path);
    
    std::cout << "🎯 TARGETED SYMBOL EXTRACTION RESULTS\n";
    std::cout << "=====================================\n";
    std::cout << "Total symbols scanned: " << result.total_symbols_scanned << "\n";
    std::cout << "Essential symbols found: " << result.found_symbols.size() << "\n";
    std::cout << "Lua bridge functions found: " << result.found_lua_bridges.size() << "\n";
    std::cout << "Missing symbols: " << result.missing_symbols.size() << "\n\n";
    
    if (!result.missing_symbols.empty()) {
        std::cout << "❌ Missing symbols:\n";
        for (const auto& missing : result.missing_symbols) {
            std::cout << "   - " << missing << "\n";
        }
        std::cout << "\n";
    }
    
    std::cout << "✅ Found essential symbols:\n";
    for (const auto& symbol : result.found_symbols) {
        std::cout << "   - " << symbol.name << " (0x" << std::hex << symbol.address << ") " 
                  << (symbol.critical ? "[CRITICAL]" : "[OPTIONAL]") << "\n";
    }
    
    // Export results
    extractor.exportToHeaderFile(result, header_path);
    extractor.exportToBinaryMappings(result, mappings_path);
    
    std::cout << "\n🎯 Ready for bg3se integration!\n";
    std::cout << "Next steps:\n";
    std::cout << "1. Include " << header_path << " in your bg3se project\n";
    std::cout << "2. Use " << mappings_path << " for binary mappings\n";
    std::cout << "3. Start with hooking esv::OsirisAutomatedDialogTask::Update\n";
    
    return 0;
}
