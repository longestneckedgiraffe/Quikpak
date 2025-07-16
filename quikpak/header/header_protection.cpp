#include "header_protection.h"
#include <algorithm>
#include <cstring>
#include <random>
#include <iostream>
#include <ctime>

namespace quikpak {

    constexpr uint32_t SECTION_ALIGNMENT = 0x1000;
    constexpr uint32_t FILE_ALIGNMENT = 0x200;
    constexpr uint32_t MIN_CODE_CAVE_SIZE = 64;
    constexpr uint32_t MAX_STUB_SIZE = 1024;

    constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
    constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;
    constexpr uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;

    constexpr uint32_t QUIK_SECTION_CHARACTERISTICS = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    std::expected<void, protection_error> header_protection::apply_protection(
        pe_file& target,
        const header_protection_config& config
    ) {
        if (!target.is_executable()) {
            return std::unexpected(protection_error::invalid_pe_file);
        }

        if (auto result = backup_headers(target); !result) {
            return result;
        }

        auto quik_section_result = create_quik_section(target);
        if (!quik_section_result) {
            return std::unexpected(quik_section_result.error());
        }
        protection_stub_rva_ = *quik_section_result;

        if (auto result = insert_protection_stub(target); !result) {
            return result;
        }

        if (auto result = modify_entry_point(target); !result) {
            return result;
        }

        if (auto result = zero_headers(target, config); !result) {
            return result;
        }

        return {};
    }

    std::expected<void, protection_error> header_protection::backup_headers(pe_file& target) {
        if (auto result = create_header_backup(target); !result) {
            return result;
        }

        original_entry_point_ = target.entry_point();
        return {};
    }

    std::expected<uint32_t, protection_error> header_protection::create_quik_section(pe_file& target) {
        uint32_t required_size = calculate_required_space(target);

        std::vector<uint8_t> section_data;

        std::string message = "THANK YOU FOR USING QUIKPAK";
        section_data.insert(section_data.end(), message.begin(), message.end());
        section_data.push_back(0);

        uint32_t timestamp = static_cast<uint32_t>(std::time(nullptr));
        uint8_t* ts_bytes = reinterpret_cast<uint8_t*>(&timestamp);
        section_data.insert(section_data.end(), ts_bytes, ts_bytes + 4);

        std::string version = "VERSION 1";
        section_data.insert(section_data.end(), version.begin(), version.end());
        section_data.push_back(0);

        std::string arch = target.is_32bit() ? "x86" : "x64";
        section_data.insert(section_data.end(), arch.begin(), arch.end());
        section_data.push_back(0);

        uint32_t protection_flags = 0x00000001;
        uint8_t* flags_bytes = reinterpret_cast<uint8_t*>(&protection_flags);
        section_data.insert(section_data.end(), flags_bytes, flags_bytes + 4);

        std::string signature = "MADE WITH <3 BY RIDHWAN ZAMAN";
        section_data.insert(section_data.end(), signature.begin(), signature.end());
        section_data.push_back(0);

        size_t stub_offset = (section_data.size() + 15) & ~15;
        section_data.resize(stub_offset, 0x90);
        section_data.resize(required_size, 0x90);

        auto section_rva_result = target.add_section(".quik", required_size, QUIK_SECTION_CHARACTERISTICS, section_data);
        if (!section_rva_result) {
            return std::unexpected(protection_error::insufficient_space);
        }

        uint32_t section_rva = *section_rva_result;
        uint32_t stub_rva = section_rva + static_cast<uint32_t>(stub_offset);

        return stub_rva;
    }

    std::expected<void, protection_error> header_protection::modify_entry_point(pe_file& target) {
        auto result = target.set_entry_point(protection_stub_rva_);
        if (!result) {
            return std::unexpected(protection_error::entry_point_modification_failed);
        }
        return {};
    }

    std::expected<void, protection_error> header_protection::zero_headers(
        pe_file& target,
        const header_protection_config& config
    ) {
        if (config.zero_dos_header) {
            zero_dos_header_fields(target);
        }

        if (config.zero_pe_signature) {
            zero_pe_header_fields(target);
        }

        if (config.zero_optional_header_fields) {
            zero_optional_header_fields(target);
        }

        if (config.encrypt_section_names) {
            encrypt_section_names(target);
        }

        if (config.modify_characteristics) {
            modify_characteristics(target);
        }

        return {};
    }

    std::expected<void, protection_error> header_protection::insert_protection_stub(pe_file& target) {
        std::vector<uint8_t> stub;

        if (target.is_32bit()) {
            auto stub_result = generate_x86_stub(original_entry_point_, protection_stub_rva_, target);
            if (!stub_result) {
                return std::unexpected(stub_result.error());
            }
            stub = std::move(*stub_result);
        }
        else if (target.is_64bit()) {
            auto stub_result = generate_x64_stub(original_entry_point_, protection_stub_rva_, target);
            if (!stub_result) {
                return std::unexpected(stub_result.error());
            }
            stub = std::move(*stub_result);
        }
        else {
            return std::unexpected(protection_error::unsupported_architecture);
        }

        auto result = target.write_data_at_rva(protection_stub_rva_, stub);
        if (!result) {
            return std::unexpected(protection_error::stub_generation_failed);
        }

        return {};
    }

    std::expected<std::vector<uint8_t>, protection_error> header_protection::generate_x86_stub(
        uint32_t original_entry_point,
        uint32_t header_restore_rva,
        const pe_file& target
    ) const {
        std::vector<uint8_t> stub;

        auto jump_stub = create_jump_to_original_x86(original_entry_point, stub.size());
        stub.insert(stub.end(), jump_stub.begin(), jump_stub.end());

        return stub;
    }

    std::expected<std::vector<uint8_t>, protection_error> header_protection::generate_x64_stub(
        uint32_t original_entry_point,
        uint32_t header_restore_rva,
        const pe_file& target
    ) const {
        std::vector<uint8_t> stub;

        auto jump_stub = create_jump_to_original_x64(original_entry_point, stub.size());
        stub.insert(stub.end(), jump_stub.begin(), jump_stub.end());

        return stub;
    }

    uint32_t header_protection::calculate_required_space(const pe_file& target) const {
        uint32_t message_size = 29;
        uint32_t timestamp_size = 4;
        uint32_t version_size = 5;
        uint32_t arch_size = 4;
        uint32_t flags_size = 4;
        uint32_t signature_size = 24;
        uint32_t alignment_padding = 16;
        uint32_t stub_size = 32;
        uint32_t extra_padding = 128;

        uint32_t total = message_size + timestamp_size + version_size + arch_size +
            flags_size + signature_size + alignment_padding + stub_size + extra_padding;

        return total;
    }

    std::expected<uint32_t, protection_error> header_protection::find_code_cave(
        const pe_file& target,
        uint32_t required_size
    ) const {
        for (const auto& section : target.sections()) {
            std::string section_name(section.name, std::find(section.name, section.name + 8, '\0'));

            if (!is_section_executable(section)) {
                continue;
            }

            if (section.size_of_raw_data > section.virtual_size) {
                uint32_t available_space = section.size_of_raw_data - section.virtual_size;

                if (available_space >= required_size) {
                    uint32_t injection_rva = section.virtual_address + section.virtual_size - required_size;
                    return injection_rva;
                }
            }

            if (section.virtual_size >= required_size + 16) {
                uint32_t injection_rva = section.virtual_address + section.virtual_size - required_size - 16;
                return injection_rva;
            }
        }

        return std::unexpected(protection_error::insufficient_space);
    }

    std::expected<void, protection_error> header_protection::create_header_backup(const pe_file& target) {
        backup_data_.dos_header = target.dos_header();
        backup_data_.pe_header = target.pe_header();
        backup_data_.section_headers = target.sections();

        if (target.is_32bit()) {
            backup_data_.optional_header_data.resize(sizeof(optional_header_32_t));
        }
        else {
            backup_data_.optional_header_data.resize(sizeof(optional_header_64_t));
        }

        return {};
    }

    void header_protection::zero_dos_header_fields(pe_file& target) {
    }

    void header_protection::zero_pe_header_fields(pe_file& target) {
    }

    void header_protection::zero_optional_header_fields(pe_file& target) {
    }

    void header_protection::encrypt_section_names(pe_file& target) {
        static const uint8_t xor_key = 0xAA;
    }

    void header_protection::modify_characteristics(pe_file& target) {
    }

    std::vector<uint8_t> header_protection::create_header_restore_stub_x86(uint32_t backup_rva) const {
        std::vector<uint8_t> stub;

        stub.push_back(0xB8);
        uint32_t* rva_ptr = reinterpret_cast<uint32_t*>(&stub[stub.size()]);
        stub.resize(stub.size() + 4);
        *rva_ptr = backup_rva;

        stub.push_back(0x90);

        return stub;
    }

    std::vector<uint8_t> header_protection::create_header_restore_stub_x64(uint32_t backup_rva) const {
        std::vector<uint8_t> stub;

        stub.push_back(0x48);
        stub.push_back(0xB8);
        uint32_t* rva_ptr = reinterpret_cast<uint32_t*>(&stub[stub.size()]);
        stub.resize(stub.size() + 4);
        *rva_ptr = backup_rva;
        stub.resize(stub.size() + 4);

        stub.push_back(0x90);

        return stub;
    }

    std::vector<uint8_t> header_protection::create_jump_to_original_x86(uint32_t original_ep, size_t current_stub_size) const {
        std::vector<uint8_t> stub;

        uint32_t jump_position = protection_stub_rva_ + static_cast<uint32_t>(current_stub_size);
        uint32_t next_instruction_rva = jump_position + 5;
        int32_t relative_offset = static_cast<int32_t>(original_ep) - static_cast<int32_t>(next_instruction_rva);

        stub.push_back(0xE9);

        uint8_t* offset_bytes = reinterpret_cast<uint8_t*>(&relative_offset);
        stub.insert(stub.end(), offset_bytes, offset_bytes + 4);

        return stub;
    }

    std::vector<uint8_t> header_protection::create_jump_to_original_x64(uint32_t original_ep, size_t current_stub_size) const {
        std::vector<uint8_t> stub;

        uint32_t jump_position = protection_stub_rva_ + static_cast<uint32_t>(current_stub_size);
        uint32_t next_instruction_rva = jump_position + 5;
        int32_t relative_offset = static_cast<int32_t>(original_ep) - static_cast<int32_t>(next_instruction_rva);

        stub.push_back(0xE9);

        uint8_t* offset_bytes = reinterpret_cast<uint8_t*>(&relative_offset);
        stub.insert(stub.end(), offset_bytes, offset_bytes + 4);

        return stub;
    }

    std::string protection_error_to_string(protection_error error) {
        switch (error) {
        case protection_error::invalid_pe_file:
            return "Invalid PE file";
        case protection_error::insufficient_space:
            return "Insufficient space for protection";
        case protection_error::entry_point_modification_failed:
            return "Failed to modify entry point";
        case protection_error::stub_generation_failed:
            return "Failed to generate protection stub";
        case protection_error::header_backup_failed:
            return "Failed to backup headers";
        case protection_error::unsupported_architecture:
            return "Unsupported architecture";
        default:
            return "Unknown protection error";
        }
    }

    bool is_section_executable(const section_header_t& section) {
        return (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    uint32_t align_to_boundary(uint32_t value, uint32_t boundary) {
        return (value + boundary - 1) & ~(boundary - 1);
    }

} // namespace quikpak