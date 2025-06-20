// RuntimePatternEnhancer.cpp - Advanced pattern matching for bg3se symbols
// This handles cases where string literal matching isn't enough

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <regex>
#include <algorithm>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

class RuntimePatternEnhancer {
private:
    struct DisassemblyPattern {
        std::string name;
        std::vector<std::vector<uint8_t>> instruction_patterns;  // x86/ARM instruction patterns
        std::vector<std::string> nearby_strings;  // Strings that should be near this function
        std::string category;
        bool critical;
        uint64_t found_address = 0;
    };
    
    // Advanced patterns for symbols that are hard to find via strings alone
    std::vector<DisassemblyPattern> advanced_patterns = {
        // App::UpdatePaths pattern - looks for path manipulation code
        {
            "App::UpdatePaths",
            {
                {0x48, 0x8b, 0x05}, // mov rax, [rip+offset] - loading global pointer
                {0x48, 0x89},       // mov [reg], reg - storing result
            },
            {"Baldur's Gate 3", "Documents"},
            "app_core",
            true
        },
        
        // GlobalAllocator patterns - memory allocation calls
        {
            "ls::GlobalAllocator::Get",
            {
                {0x48, 0x83, 0xec}, // sub rsp, imm8 - stack allocation
                {0xe8},             // call rel32 - function call
                {0x48, 0x85, 0xc0}, // test rax, rax - null check
            },
            {"Allocator", "Memory"},
            "memory",
            true
        },
        
        // ECS Update patterns - entity system update loops  
        {
            "ecs::EntityWorld::Update",
            {
                {0x48, 0x8b}, // mov reg, [reg+offset] - loading entity data
                {0xff, 0x90}, // call [rax+offset] - virtual function call
                {0x48, 0xff, 0xc0}, // inc rax - iterator increment
            },
            {"EntityWorld", "Update", "Component"},
            "ecs",
            true
        },
        
        // Game state machine patterns
        {
            "ecl::GameStateMachine::Update",
            {
                {0x83, 0xf8}, // cmp eax, imm8 - state comparison
                {0x74},       // je rel8 - conditional jump
                {0x89},       // mov [mem], reg - state assignment
            },
            {"CLIENT STATE SWAP", "GameState"},
            "state",
            true
        },
        
        // RPGStats::Load patterns - mod loading entry point
        {
            "RPGStats::Load",
            {
                {0x48, 0x8d, 0x15}, // lea rdx, [rip+offset] - loading string address
                {0xe8},             // call rel32
                {0x84, 0xc0},       // test al, al - return value check
            },
            {"Stats", "Load", "Data"},
            "stats",
            true
        },
        
        // File reader patterns - mod file loading
        {
            "ls::FileReader::ctor",
            {
                {0x48, 0x89, 0x4c, 0x24}, // mov [rsp+offset], rcx - saving file path
                {0x4c, 0x8d, 0x05},        // lea r8, [rip+offset] - loading filename
                {0xe8},                    // call rel32
            },
            {"FileReader", ".txt", "ItemCombos"},
            "io",
            true
        }
    };
    
    std::unordered_map<uint64_t, std::string> symbol_table;
    std::unordered_map<std::string, uint64_t> string_table;
    std::vector<uint8_t> text_section_data;
    uint64_t text_section_base = 0;

public:
    struct EnhancedResult {
        std::vector<DisassemblyPattern> found_patterns;
        std::vector<std::string> missing_patterns;
        int confidence_score = 0;
    };
    
    EnhancedResult enhancePatternSearch(const std::string& binary_path, 
                                       const std::unordered_map<std::string, uint64_t>& initial_symbols) {
        EnhancedResult result;
        
        // Load initial symbol information
        for (const auto& [name, addr] : initial_symbols) {
            symbol_table[addr] = name;
        }
        
        // Load and analyze the binary
        if (!loadBinary(binary_path)) {
            std::cerr << "Failed to load binary for enhanced analysis\n";
            return result;
        }
        
        // Search for each advanced pattern
        searchAdvancedPatterns(result);
        
        return result;
    }
    
    void exportEnhancedResults(const EnhancedResult& result, const std::string& output_path) {
        std::ofstream out(output_path);
        if (!out) {
            std::cerr << "Failed to create enhanced results file\n";
            return;
        }
        
        out << "// Enhanced Pattern Search Results\n";
        out << "// Generated using disassembly analysis\n\n";
        out << "#pragma once\n\n";
        out << "namespace bg3se::macos::enhanced {\n\n";
        
        for (const auto& pattern : result.found_patterns) {
            if (pattern.found_address != 0) {
                std::string safe_name = makeSafeName(pattern.name);
                out << "    // Found via advanced pattern matching\n";
                out << "    constexpr uintptr_t " << safe_name << " = 0x" 
                    << std::hex << pattern.found_address << "; // " << pattern.name << "\n\n";
            }
        }
        
        out << "} // namespace bg3se::macos::enhanced\n";
        out.close();
        
        std::cout << "✅ Enhanced pattern results exported to " << output_path << std::endl;
    }

private:
    bool loadBinary(const std::string& binary_path) {
        std::ifstream file(binary_path, std::ios::binary);
        if (!file) return false;
        
        // Skip to ARM64 slice if needed (simplified)
        mach_header_64 header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        if (header.magic != MH_MAGIC_64) return false;
        
        // Find __TEXT segment and extract it for analysis
        uint64_t offset = sizeof(mach_header_64);
        for (uint32_t i = 0; i < header.ncmds; ++i) {
            file.seekg(offset);
            
            uint32_t cmd, cmdsize;
            file.read(reinterpret_cast<char*>(&cmd), 4);
            file.read(reinterpret_cast<char*>(&cmdsize), 4);
            
            if (cmd == LC_SEGMENT_64) {
                file.seekg(offset);
                segment_command_64 seg;
                file.read(reinterpret_cast<char*>(&seg), sizeof(seg));
                
                std::string segname(reinterpret_cast<char*>(seg.segname), 
                                  strnlen(reinterpret_cast<char*>(seg.segname), 16));
                
                if (segname == "__TEXT") {
                    text_section_base = seg.vmaddr;
                    text_section_data.resize(seg.filesize);
                    file.seekg(seg.fileoff);
                    file.read(reinterpret_cast<char*>(text_section_data.data()), seg.filesize);
                    break;
                }
            }
            
            offset += cmdsize;
        }
        
        return !text_section_data.empty();
    }
    
    void searchAdvancedPatterns(EnhancedResult& result) {
        std::cout << "🔍 Running advanced pattern analysis...\n";
        
        for (auto& pattern : advanced_patterns) {
            std::vector<uint64_t> candidates = findInstructionPatterns(pattern);
            
            if (!candidates.empty()) {
                // Score candidates based on nearby strings and code patterns
                uint64_t best_candidate = 0;
                int best_score = 0;
                
                for (uint64_t candidate : candidates) {
                    int score = scoreCandidate(candidate, pattern);
                    if (score > best_score) {
                        best_score = score;
                        best_candidate = candidate;
                    }
                }
                
                if (best_score > 3) { // Minimum confidence threshold
                    pattern.found_address = best_candidate;
                    result.found_patterns.push_back(pattern);
                    result.confidence_score += best_score;
                    
                    std::cout << "   ✅ Found " << pattern.name << " at 0x" << std::hex 
                              << best_candidate << " (confidence: " << best_score << ")\n";
                } else {
                    result.missing_patterns.push_back(pattern.name);
                    std::cout << "   ❌ Low confidence for " << pattern.name 
                              << " (best score: " << best_score << ")\n";
                }
            } else {
                result.missing_patterns.push_back(pattern.name);
                std::cout << "   ❌ No candidates found for " << pattern.name << "\n";
            }
        }
    }
    
    std::vector<uint64_t> findInstructionPatterns(const DisassemblyPattern& pattern) {
        std::vector<uint64_t> candidates;
        
        // Search for instruction patterns in the text section
        for (size_t i = 0; i < text_section_data.size() - 16; ++i) {
            bool all_patterns_found = true;
            
            // Check if all instruction patterns are present nearby
            for (const auto& inst_pattern : pattern.instruction_patterns) {
                bool pattern_found = false;
                
                // Search within a 64-byte window
                for (size_t j = 0; j < 64 && i + j + inst_pattern.size() < text_section_data.size(); ++j) {
                    bool matches = true;
                    for (size_t k = 0; k < inst_pattern.size(); ++k) {
                        if (text_section_data[i + j + k] != inst_pattern[k]) {
                            matches = false;
                            break;
                        }
                    }
                    if (matches) {
                        pattern_found = true;
                        break;
                    }
                }
                
                if (!pattern_found) {
                    all_patterns_found = false;
                    break;
                }
            }
            
            if (all_patterns_found) {
                uint64_t candidate_addr = text_section_base + i;
                candidates.push_back(candidate_addr);
            }
        }
        
        return candidates;
    }
    
    int scoreCandidate(uint64_t address, const DisassemblyPattern& pattern) {
        int score = 0;
        
        // Score based on nearby strings
        for (const auto& target_string : pattern.nearby_strings) {
            if (hasNearbyStringReference(address, target_string)) {
                score += 3;
            }
        }
        
        // Score based on nearby symbols
        for (const auto& [sym_addr, sym_name] : symbol_table) {
            if (std::abs(static_cast<int64_t>(address) - static_cast<int64_t>(sym_addr)) < 0x1000) {
                if (sym_name.find(pattern.name.substr(0, 8)) != std::string::npos) {
                    score += 5;
                }
            }
        }
        
        // Score based on function prologue/epilogue patterns
        if (hasValidFunctionStructure(address)) {
            score += 2;
        }
        
        return score;
    }
    
    bool hasNearbyStringReference(uint64_t address, const std::string& target) {
        // Simplified: check if any known string contains the target
        for (const auto& [str, str_addr] : string_table) {
            if (str.find(target) != std::string::npos) {
                if (std::abs(static_cast<int64_t>(address) - static_cast<int64_t>(str_addr)) < 0x10000) {
                    return true;
                }
            }
        }
        return false;
    }
    
    bool hasValidFunctionStructure(uint64_t address) {
        // Check for common ARM64/x64 function prologue patterns
        if (address < text_section_base || address >= text_section_base + text_section_data.size()) {
            return false;
        }
        
        size_t offset = address - text_section_base;
        if (offset + 8 >= text_section_data.size()) return false;
        
        // Look for common function prologue patterns (simplified)
        uint8_t* bytes = &text_section_data[offset];
        
        // ARM64 function prologue: stp x29, x30, [sp, #-16]!
        if (bytes[0] == 0xfd && bytes[1] == 0x7b && bytes[2] == 0xbf && bytes[3] == 0xa9) {
            return true;
        }
        
        // x64 function prologue: push rbp; mov rbp, rsp
        if (bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x89 && bytes[3] == 0xe5) {
            return true;
        }
        
        return false;
    }
    
    std::string makeSafeName(const std::string& name) {
        std::string safe = name;
        for (char& c : safe) {
            if (!std::isalnum(c)) c = '_';
        }
        return safe;
    }
};

// Usage example
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary> [initial_symbols.txt]\n";
        return 1;
    }
    
    RuntimePatternEnhancer enhancer;
    std::unordered_map<std::string, uint64_t> initial_symbols;
    
    // Load initial symbol results if provided
    if (argc > 2) {
        std::ifstream symbols_file(argv[2]);
        std::string line;
        while (std::getline(symbols_file, line)) {
            // Parse format: "symbol_name 0x1234567890"
            size_t space_pos = line.find(' ');
            if (space_pos != std::string::npos) {
                std::string name = line.substr(0, space_pos);
                std::string addr_str = line.substr(space_pos + 1);
                if (addr_str.substr(0, 2) == "0x") {
                    uint64_t addr = std::stoull(addr_str.substr(2), nullptr, 16);
                    initial_symbols[name] = addr;
                }
            }
        }
    }
    
    auto result = enhancer.enhancePatternSearch(argv[1], initial_symbols);
    
    std::cout << "\n🎯 ENHANCED PATTERN SEARCH RESULTS\n";
    std::cout << "=====================================\n";
    std::cout << "Advanced patterns found: " << result.found_patterns.size() << "\n";
    std::cout << "Missing patterns: " << result.missing_patterns.size() << "\n";
    std::cout << "Overall confidence: " << result.confidence_score << "\n\n";
    
    enhancer.exportEnhancedResults(result, "bg3se_enhanced_symbols.h");
    
    return 0;
}
