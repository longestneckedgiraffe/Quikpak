#pragma once

#include "../pe/pe_parser.h"
#include <cstdint>
#include <vector>
#include <expected>

namespace quikpak {

    enum class protection_error {
        invalid_pe_file,
        insufficient_space,
        entry_point_modification_failed,
        stub_generation_failed,
        header_backup_failed,
        unsupported_architecture
    };

    struct header_protection_config {
        bool zero_dos_header = true;
        bool zero_pe_signature = true;
        bool zero_optional_header_fields = true;
        bool encrypt_section_names = true;
        bool modify_characteristics = true;
    };

    class header_protection {
    public:
        header_protection() = default;
        ~header_protection() = default;

        header_protection(const header_protection&) = delete;
        header_protection& operator=(const header_protection&) = delete;
        header_protection(header_protection&&) = default;
        header_protection& operator=(header_protection&&) = default;

        std::expected<void, protection_error> apply_protection(
            pe_file& target,
            const header_protection_config& config = {}
        );

        std::expected<void, protection_error> backup_headers(pe_file& target);
        std::expected<uint32_t, protection_error> create_quik_section(pe_file& target);
        std::expected<void, protection_error> modify_entry_point(pe_file& target);
        std::expected<void, protection_error> zero_headers(pe_file& target, const header_protection_config& config);
        std::expected<void, protection_error> insert_protection_stub(pe_file& target);

        std::expected<std::vector<uint8_t>, protection_error> generate_x86_stub(
            uint32_t original_entry_point,
            uint32_t header_restore_rva,
            const pe_file& target
        ) const;

        std::expected<std::vector<uint8_t>, protection_error> generate_x64_stub(
            uint32_t original_entry_point,
            uint32_t header_restore_rva,
            const pe_file& target
        ) const;

        [[nodiscard]] uint32_t calculate_required_space(const pe_file& target) const;
        [[nodiscard]] std::expected<uint32_t, protection_error> find_code_cave(const pe_file& target, uint32_t required_size) const;

    private:
        struct header_backup {
            dos_header_t dos_header;
            pe_header_t pe_header;
            std::vector<uint8_t> optional_header_data;
            std::vector<section_header_t> section_headers;
        };

        header_backup backup_data_;
        uint32_t protection_stub_rva_ = 0;
        uint32_t original_entry_point_ = 0;

        std::expected<void, protection_error> create_header_backup(const pe_file& target);
        std::expected<void, protection_error> find_injection_point(pe_file& target);
        std::expected<std::vector<uint8_t>, protection_error> create_restore_data() const;

        void zero_dos_header_fields(pe_file& target);
        void zero_pe_header_fields(pe_file& target);
        void zero_optional_header_fields(pe_file& target);
        void encrypt_section_names(pe_file& target);
        void modify_characteristics(pe_file& target);

        std::vector<uint8_t> create_header_restore_stub_x86(uint32_t backup_rva) const;
        std::vector<uint8_t> create_header_restore_stub_x64(uint32_t backup_rva) const;
        std::vector<uint8_t> create_jump_to_original_x86(uint32_t original_ep, size_t current_stub_size) const;
        std::vector<uint8_t> create_jump_to_original_x64(uint32_t original_ep, size_t current_stub_size) const;
    };

    [[nodiscard]] std::string protection_error_to_string(protection_error error);
    [[nodiscard]] bool is_section_executable(const section_header_t& section);
    [[nodiscard]] uint32_t align_to_boundary(uint32_t value, uint32_t boundary);

} // namespace quikpak