#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <expected>
#include <span>

namespace quikpak {

    struct dos_header_t {
        uint16_t e_magic;
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;
        uint16_t e_cparhdr;
        uint16_t e_minalloc;
        uint16_t e_maxalloc;
        uint16_t e_ss;
        uint16_t e_sp;
        uint16_t e_csum;
        uint16_t e_ip;
        uint16_t e_cs;
        uint16_t e_lfarlc;
        uint16_t e_ovno;
        uint16_t e_res[4];
        uint16_t e_oemid;
        uint16_t e_oeminfo;
        uint16_t e_res2[10];
        uint32_t e_lfanew;
    };

    struct pe_header_t {
        uint32_t signature;
        uint16_t machine;
        uint16_t number_of_sections;
        uint32_t time_date_stamp;
        uint32_t pointer_to_symbol_table;
        uint32_t number_of_symbols;
        uint16_t size_of_optional_header;
        uint16_t characteristics;
    };

    struct optional_header_32_t {
        uint16_t magic;
        uint8_t major_linker_version;
        uint8_t minor_linker_version;
        uint32_t size_of_code;
        uint32_t size_of_initialized_data;
        uint32_t size_of_uninitialized_data;
        uint32_t address_of_entry_point;
        uint32_t base_of_code;
        uint32_t base_of_data;
        uint32_t image_base;
        uint32_t section_alignment;
        uint32_t file_alignment;
        uint16_t major_operating_system_version;
        uint16_t minor_operating_system_version;
        uint16_t major_image_version;
        uint16_t minor_image_version;
        uint16_t major_subsystem_version;
        uint16_t minor_subsystem_version;
        uint32_t win32_version_value;
        uint32_t size_of_image;
        uint32_t size_of_headers;
        uint32_t checksum;
        uint16_t subsystem;
        uint16_t dll_characteristics;
        uint32_t size_of_stack_reserve;
        uint32_t size_of_stack_commit;
        uint32_t size_of_heap_reserve;
        uint32_t size_of_heap_commit;
        uint32_t loader_flags;
        uint32_t number_of_rva_and_sizes;
    };

    struct optional_header_64_t {
        uint16_t magic;
        uint8_t major_linker_version;
        uint8_t minor_linker_version;
        uint32_t size_of_code;
        uint32_t size_of_initialized_data;
        uint32_t size_of_uninitialized_data;
        uint32_t address_of_entry_point;
        uint32_t base_of_code;
        uint64_t image_base;
        uint32_t section_alignment;
        uint32_t file_alignment;
        uint16_t major_operating_system_version;
        uint16_t minor_operating_system_version;
        uint16_t major_image_version;
        uint16_t minor_image_version;
        uint16_t major_subsystem_version;
        uint16_t minor_subsystem_version;
        uint32_t win32_version_value;
        uint32_t size_of_image;
        uint32_t size_of_headers;
        uint32_t checksum;
        uint16_t subsystem;
        uint16_t dll_characteristics;
        uint64_t size_of_stack_reserve;
        uint64_t size_of_stack_commit;
        uint64_t size_of_heap_reserve;
        uint64_t size_of_heap_commit;
        uint32_t loader_flags;
        uint32_t number_of_rva_and_sizes;
    };

    struct section_header_t {
        char name[8];
        uint32_t virtual_size;
        uint32_t virtual_address;
        uint32_t size_of_raw_data;
        uint32_t pointer_to_raw_data;
        uint32_t pointer_to_relocations;
        uint32_t pointer_to_line_numbers;
        uint16_t number_of_relocations;
        uint16_t number_of_line_numbers;
        uint32_t characteristics;
    };

    enum class parse_error {
        file_not_found,
        invalid_dos_header,
        invalid_pe_header,
        invalid_optional_header,
        invalid_section_headers,
        unsupported_architecture,
        file_too_small,
        corrupted_data
    };

    class pe_file {
    public:
        enum class architecture {
            x86,
            x64,
            unknown
        };

        pe_file() = default;
        ~pe_file() = default;

        pe_file(const pe_file&) = delete;
        pe_file& operator=(const pe_file&) = delete;
        pe_file(pe_file&&) = default;
        pe_file& operator=(pe_file&&) = default;

        static std::expected<pe_file, parse_error> from_file(const std::string& file_path);
        static std::expected<pe_file, parse_error> from_memory(std::span<const uint8_t> data);

        [[nodiscard]] const dos_header_t& dos_header() const noexcept { return dos_header_; }
        [[nodiscard]] const pe_header_t& pe_header() const noexcept { return pe_header_; }
        [[nodiscard]] const std::vector<section_header_t>& sections() const noexcept { return sections_; }
        [[nodiscard]] architecture arch() const noexcept { return arch_; }
        [[nodiscard]] uint32_t entry_point() const noexcept;
        [[nodiscard]] uint64_t image_base() const noexcept;
        [[nodiscard]] uint32_t size_of_image() const noexcept;
        [[nodiscard]] const std::vector<uint8_t>& raw_data() const noexcept { return raw_data_; }
        [[nodiscard]] std::vector<uint8_t>& raw_data() noexcept { return raw_data_; }

        [[nodiscard]] std::expected<section_header_t*, parse_error> find_section(const std::string& name);
        [[nodiscard]] std::expected<std::span<uint8_t>, parse_error> get_section_data(const section_header_t& section);
        [[nodiscard]] std::expected<std::span<const uint8_t>, parse_error> get_section_data(const section_header_t& section) const;
        [[nodiscard]] uint32_t rva_to_file_offset(uint32_t rva) const;

        [[nodiscard]] bool is_32bit() const noexcept { return arch_ == architecture::x86; }
        [[nodiscard]] bool is_64bit() const noexcept { return arch_ == architecture::x64; }
        [[nodiscard]] bool is_dll() const noexcept;
        [[nodiscard]] bool is_executable() const noexcept;

        std::expected<void, parse_error> save_to_file(const std::string& file_path) const;

        std::expected<void, parse_error> set_entry_point(uint32_t new_entry_point);
        std::expected<void, parse_error> write_data_at_rva(uint32_t rva, const std::vector<uint8_t>& data);
        std::expected<void, parse_error> write_data_at_offset(size_t offset, const std::vector<uint8_t>& data);
        std::expected<void, parse_error> modify_dos_header(const dos_header_t& new_header);
        std::expected<void, parse_error> modify_pe_header(const pe_header_t& new_header);
        std::expected<void, parse_error> modify_section_header(size_t section_index, const section_header_t& new_header);
        std::expected<uint32_t, parse_error> add_section(const std::string& name, uint32_t size, uint32_t characteristics, const std::vector<uint8_t>& data = {});

    private:
        std::vector<uint8_t> raw_data_;
        dos_header_t dos_header_{};
        pe_header_t pe_header_{};
        optional_header_32_t optional_header_32_{};
        optional_header_64_t optional_header_64_{};
        std::vector<section_header_t> sections_;
        architecture arch_ = architecture::unknown;

        std::expected<void, parse_error> parse_headers();
        std::expected<void, parse_error> parse_dos_header();
        std::expected<void, parse_error> parse_pe_header();
        std::expected<void, parse_error> parse_optional_header();
        std::expected<void, parse_error> parse_sections();

        [[nodiscard]] bool validate_dos_header() const noexcept;
        [[nodiscard]] bool validate_pe_header() const noexcept;
        [[nodiscard]] bool validate_optional_header() const noexcept;
        [[nodiscard]] bool validate_sections() const noexcept;

        template<typename T>
        [[nodiscard]] std::expected<T, parse_error> read_at_offset(size_t offset) const;

        template<typename T>
        [[nodiscard]] std::expected<void, parse_error> write_at_offset(size_t offset, const T& data);
    };

    [[nodiscard]] std::string parse_error_to_string(parse_error error);
    [[nodiscard]] std::string architecture_to_string(pe_file::architecture arch);

} // namespace quikpak