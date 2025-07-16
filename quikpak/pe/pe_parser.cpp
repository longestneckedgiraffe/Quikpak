#include "pe_parser.h"
#include <fstream>
#include <algorithm>
#include <cstring>
#include <cstddef>
#include <format>

namespace quikpak {

    constexpr uint16_t DOS_SIGNATURE = 0x5A4D;
    constexpr uint32_t PE_SIGNATURE = 0x00004550;
    constexpr uint16_t OPTIONAL_HEADER_32_MAGIC = 0x10b;
    constexpr uint16_t OPTIONAL_HEADER_64_MAGIC = 0x20b;
    constexpr uint16_t IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
    constexpr uint16_t IMAGE_FILE_DLL = 0x2000;

    std::expected<pe_file, parse_error> pe_file::from_file(const std::string& file_path) {
        std::ifstream file(file_path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return std::unexpected(parse_error::file_not_found);
        }

        auto file_size = file.tellg();
        if (file_size < sizeof(dos_header_t)) {
            return std::unexpected(parse_error::file_too_small);
        }

        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(static_cast<size_t>(file_size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), file_size)) {
            return std::unexpected(parse_error::corrupted_data);
        }

        return from_memory(buffer);
    }

    std::expected<pe_file, parse_error> pe_file::from_memory(std::span<const uint8_t> data) {
        pe_file file;
        file.raw_data_.assign(data.begin(), data.end());

        if (auto result = file.parse_headers(); !result) {
            return std::unexpected(result.error());
        }

        return file;
    }

    uint32_t pe_file::entry_point() const noexcept {
        switch (arch_) {
        case architecture::x86:
            return optional_header_32_.address_of_entry_point;
        case architecture::x64:
            return optional_header_64_.address_of_entry_point;
        default:
            return 0;
        }
    }

    uint64_t pe_file::image_base() const noexcept {
        switch (arch_) {
        case architecture::x86:
            return optional_header_32_.image_base;
        case architecture::x64:
            return optional_header_64_.image_base;
        default:
            return 0;
        }
    }

    uint32_t pe_file::size_of_image() const noexcept {
        switch (arch_) {
        case architecture::x86:
            return optional_header_32_.size_of_image;
        case architecture::x64:
            return optional_header_64_.size_of_image;
        default:
            return 0;
        }
    }

    bool pe_file::is_dll() const noexcept {
        return (pe_header_.characteristics & IMAGE_FILE_DLL) != 0;
    }

    bool pe_file::is_executable() const noexcept {
        return (pe_header_.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0;
    }

    std::expected<section_header_t*, parse_error> pe_file::find_section(const std::string& name) {
        auto it = std::find_if(sections_.begin(), sections_.end(),
            [&name](const section_header_t& section) {
                return std::strncmp(section.name, name.c_str(), 8) == 0;
            });

        if (it == sections_.end()) {
            return std::unexpected(parse_error::invalid_section_headers);
        }

        return &(*it);
    }

    std::expected<std::span<uint8_t>, parse_error> pe_file::get_section_data(const section_header_t& section) {
        if (section.pointer_to_raw_data == 0 || section.size_of_raw_data == 0) {
            return std::unexpected(parse_error::invalid_section_headers);
        }

        if (section.pointer_to_raw_data + section.size_of_raw_data > raw_data_.size()) {
            return std::unexpected(parse_error::corrupted_data);
        }

        return std::span<uint8_t>(
            raw_data_.data() + section.pointer_to_raw_data,
            section.size_of_raw_data
        );
    }

    std::expected<std::span<const uint8_t>, parse_error> pe_file::get_section_data(const section_header_t& section) const {
        if (section.pointer_to_raw_data == 0 || section.size_of_raw_data == 0) {
            return std::unexpected(parse_error::invalid_section_headers);
        }

        if (section.pointer_to_raw_data + section.size_of_raw_data > raw_data_.size()) {
            return std::unexpected(parse_error::corrupted_data);
        }

        return std::span<const uint8_t>(
            raw_data_.data() + section.pointer_to_raw_data,
            section.size_of_raw_data
        );
    }

    uint32_t pe_file::rva_to_file_offset(uint32_t rva) const {
        for (const auto& section : sections_) {
            uint32_t section_start = section.virtual_address;
            uint32_t section_end = section_start + section.virtual_size;

            if (rva >= section_start && rva < section_end) {
                return section.pointer_to_raw_data + (rva - section_start);
            }
        }

        return 0;
    }

    std::expected<void, parse_error> pe_file::save_to_file(const std::string& file_path) const {
        std::ofstream file(file_path, std::ios::binary);
        if (!file.is_open()) {
            return std::unexpected(parse_error::file_not_found);
        }

        if (!file.write(reinterpret_cast<const char*>(raw_data_.data()), raw_data_.size())) {
            return std::unexpected(parse_error::corrupted_data);
        }

        return {};
    }

    std::expected<void, parse_error> pe_file::set_entry_point(uint32_t new_entry_point) {
        switch (arch_) {
        case architecture::x86: {
            optional_header_32_.address_of_entry_point = new_entry_point;
            size_t offset = dos_header_.e_lfanew + sizeof(pe_header_t) + offsetof(optional_header_32_t, address_of_entry_point);
            auto result = write_at_offset(offset, new_entry_point);
            if (!result) {
                return std::unexpected(result.error());
            }
            return {};
        }
        case architecture::x64: {
            optional_header_64_.address_of_entry_point = new_entry_point;
            size_t offset = dos_header_.e_lfanew + sizeof(pe_header_t) + offsetof(optional_header_64_t, address_of_entry_point);
            auto result = write_at_offset(offset, new_entry_point);
            if (!result) {
                return std::unexpected(result.error());
            }
            return {};
        }
        default:
            return std::unexpected(parse_error::unsupported_architecture);
        }
    }

    std::expected<void, parse_error> pe_file::write_data_at_rva(uint32_t rva, const std::vector<uint8_t>& data) {
        uint32_t file_offset = rva_to_file_offset(rva);
        if (file_offset == 0) {
            return std::unexpected(parse_error::invalid_section_headers);
        }

        return write_data_at_offset(file_offset, data);
    }

    std::expected<void, parse_error> pe_file::write_data_at_offset(size_t offset, const std::vector<uint8_t>& data) {
        if (offset + data.size() > raw_data_.size()) {
            return std::unexpected(parse_error::file_too_small);
        }

        std::memcpy(raw_data_.data() + offset, data.data(), data.size());
        return {};
    }

    std::expected<void, parse_error> pe_file::modify_dos_header(const dos_header_t& new_header) {
        dos_header_ = new_header;
        auto result = write_at_offset(0, new_header);
        if (!result) {
            return std::unexpected(result.error());
        }
        return {};
    }

    std::expected<void, parse_error> pe_file::modify_pe_header(const pe_header_t& new_header) {
        pe_header_ = new_header;
        auto result = write_at_offset(dos_header_.e_lfanew, new_header);
        if (!result) {
            return std::unexpected(result.error());
        }
        return {};
    }

    std::expected<void, parse_error> pe_file::modify_section_header(size_t section_index, const section_header_t& new_header) {
        if (section_index >= sections_.size()) {
            return std::unexpected(parse_error::invalid_section_headers);
        }

        sections_[section_index] = new_header;

        size_t sections_offset = dos_header_.e_lfanew + sizeof(pe_header_t) + pe_header_.size_of_optional_header;
        size_t section_offset = sections_offset + (section_index * sizeof(section_header_t));

        auto result = write_at_offset(section_offset, new_header);
        if (!result) {
            return std::unexpected(result.error());
        }
        return {};
    }

    std::expected<uint32_t, parse_error> pe_file::add_section(
        const std::string& name,
        uint32_t size,
        uint32_t characteristics,
        const std::vector<uint8_t>& data
    ) {
        constexpr uint32_t SECTION_ALIGNMENT = 0x1000;
        constexpr uint32_t FILE_ALIGNMENT = 0x200;

        section_header_t new_section = {};
        size_t name_len = std::min(name.length(), size_t(8));

        std::memset(new_section.name, 0, 8);
        if (!name.empty() && name_len > 0) {
            std::memcpy(new_section.name, name.c_str(), name_len);
            if (name_len == 8) {
                new_section.name[7] = '\0';
            }
        }

        uint32_t new_virtual_address = SECTION_ALIGNMENT;
        if (!sections_.empty()) {
            const auto& last_section = sections_.back();
            uint32_t last_section_end = last_section.virtual_address +
                ((last_section.virtual_size + SECTION_ALIGNMENT - 1) & ~(SECTION_ALIGNMENT - 1));
            new_virtual_address = last_section_end;
        }

        uint32_t new_file_offset = 0;
        if (!sections_.empty()) {
            const auto& last_section = sections_.back();
            uint32_t last_section_file_end = last_section.pointer_to_raw_data + last_section.size_of_raw_data;
            new_file_offset = (last_section_file_end + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1);
        }
        else {
            uint32_t headers_size = dos_header_.e_lfanew + sizeof(pe_header_t) + pe_header_.size_of_optional_header +
                (pe_header_.number_of_sections + 1) * sizeof(section_header_t);
            new_file_offset = (headers_size + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1);
        }

        uint32_t aligned_size = (size + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1);

        new_section.virtual_address = new_virtual_address;
        new_section.virtual_size = size;
        new_section.pointer_to_raw_data = new_file_offset;
        new_section.size_of_raw_data = aligned_size;
        new_section.characteristics = characteristics;
        new_section.pointer_to_relocations = 0;
        new_section.pointer_to_line_numbers = 0;
        new_section.number_of_relocations = 0;
        new_section.number_of_line_numbers = 0;

        size_t new_file_size = new_file_offset + aligned_size;
        if (new_file_size > raw_data_.size()) {
            raw_data_.resize(new_file_size, 0);
        }

        if (!data.empty()) {
            size_t data_size = std::min(data.size(), size_t(size));
            std::memcpy(raw_data_.data() + new_file_offset, data.data(), data_size);
        }

        sections_.push_back(new_section);

        pe_header_.number_of_sections++;
        auto pe_result = write_at_offset(dos_header_.e_lfanew, pe_header_);
        if (!pe_result) {
            return std::unexpected(pe_result.error());
        }

        size_t sections_offset = dos_header_.e_lfanew + sizeof(pe_header_t) + pe_header_.size_of_optional_header;
        size_t new_section_offset = sections_offset + ((sections_.size() - 1) * sizeof(section_header_t));
        auto section_result = write_at_offset(new_section_offset, new_section);
        if (!section_result) {
            return std::unexpected(section_result.error());
        }

        uint32_t new_image_size = new_virtual_address + ((size + SECTION_ALIGNMENT - 1) & ~(SECTION_ALIGNMENT - 1));

        if (arch_ == architecture::x86) {
            optional_header_32_.size_of_image = new_image_size;
            size_t size_offset = dos_header_.e_lfanew + sizeof(pe_header_t) + offsetof(optional_header_32_t, size_of_image);
            auto size_result = write_at_offset(size_offset, new_image_size);
            if (!size_result) {
                return std::unexpected(size_result.error());
            }
        }
        else if (arch_ == architecture::x64) {
            optional_header_64_.size_of_image = new_image_size;
            size_t size_offset = dos_header_.e_lfanew + sizeof(pe_header_t) + offsetof(optional_header_64_t, size_of_image);
            auto size_result = write_at_offset(size_offset, new_image_size);
            if (!size_result) {
                return std::unexpected(size_result.error());
            }
        }

        return new_virtual_address;
    }

    std::expected<void, parse_error> pe_file::parse_headers() {
        if (auto result = parse_dos_header(); !result) {
            return result;
        }

        if (auto result = parse_pe_header(); !result) {
            return result;
        }

        if (auto result = parse_optional_header(); !result) {
            return result;
        }

        if (auto result = parse_sections(); !result) {
            return result;
        }

        return {};
    }

    std::expected<void, parse_error> pe_file::parse_dos_header() {
        if (auto header = read_at_offset<dos_header_t>(0)) {
            dos_header_ = *header;
            if (!validate_dos_header()) {
                return std::unexpected(parse_error::invalid_dos_header);
            }
            return {};
        }
        else {
            return std::unexpected(header.error());
        }
    }

    std::expected<void, parse_error> pe_file::parse_pe_header() {
        if (auto header = read_at_offset<pe_header_t>(dos_header_.e_lfanew)) {
            pe_header_ = *header;
            if (!validate_pe_header()) {
                return std::unexpected(parse_error::invalid_pe_header);
            }
            return {};
        }
        else {
            return std::unexpected(header.error());
        }
    }

    std::expected<void, parse_error> pe_file::parse_optional_header() {
        size_t optional_header_offset = dos_header_.e_lfanew + sizeof(pe_header_t);

        if (auto magic = read_at_offset<uint16_t>(optional_header_offset)) {
            if (*magic == OPTIONAL_HEADER_32_MAGIC) {
                arch_ = architecture::x86;
                if (auto header = read_at_offset<optional_header_32_t>(optional_header_offset)) {
                    optional_header_32_ = *header;
                }
                else {
                    return std::unexpected(header.error());
                }
            }
            else if (*magic == OPTIONAL_HEADER_64_MAGIC) {
                arch_ = architecture::x64;
                if (auto header = read_at_offset<optional_header_64_t>(optional_header_offset)) {
                    optional_header_64_ = *header;
                }
                else {
                    return std::unexpected(header.error());
                }
            }
            else {
                return std::unexpected(parse_error::unsupported_architecture);
            }
        }
        else {
            return std::unexpected(magic.error());
        }

        if (!validate_optional_header()) {
            return std::unexpected(parse_error::invalid_optional_header);
        }

        return {};
    }

    std::expected<void, parse_error> pe_file::parse_sections() {
        size_t sections_offset = dos_header_.e_lfanew + sizeof(pe_header_t) + pe_header_.size_of_optional_header;

        sections_.reserve(pe_header_.number_of_sections);

        for (uint16_t i = 0; i < pe_header_.number_of_sections; ++i) {
            size_t section_offset = sections_offset + (i * sizeof(section_header_t));

            if (auto section = read_at_offset<section_header_t>(section_offset)) {
                sections_.push_back(*section);
            }
            else {
                return std::unexpected(section.error());
            }
        }

        if (!validate_sections()) {
            return std::unexpected(parse_error::invalid_section_headers);
        }

        return {};
    }

    bool pe_file::validate_dos_header() const noexcept {
        return dos_header_.e_magic == DOS_SIGNATURE &&
            dos_header_.e_lfanew > 0 &&
            dos_header_.e_lfanew < raw_data_.size() - sizeof(pe_header_t);
    }

    bool pe_file::validate_pe_header() const noexcept {
        return pe_header_.signature == PE_SIGNATURE &&
            pe_header_.number_of_sections > 0 &&
            pe_header_.number_of_sections < 100 &&
            pe_header_.size_of_optional_header > 0;
    }

    bool pe_file::validate_optional_header() const noexcept {
        switch (arch_) {
        case architecture::x86:
            return optional_header_32_.magic == OPTIONAL_HEADER_32_MAGIC &&
                optional_header_32_.size_of_image > 0 &&
                optional_header_32_.size_of_headers > 0;
        case architecture::x64:
            return optional_header_64_.magic == OPTIONAL_HEADER_64_MAGIC &&
                optional_header_64_.size_of_image > 0 &&
                optional_header_64_.size_of_headers > 0;
        default:
            return false;
        }
    }

    bool pe_file::validate_sections() const noexcept {
        for (const auto& section : sections_) {
            if (section.pointer_to_raw_data > 0 && section.size_of_raw_data > 0) {
                if (section.pointer_to_raw_data + section.size_of_raw_data > raw_data_.size()) {
                    return false;
                }
            }

            if (section.virtual_address > size_of_image()) {
                return false;
            }
        }

        return true;
    }

    template<typename T>
    std::expected<T, parse_error> pe_file::read_at_offset(size_t offset) const {
        if (offset + sizeof(T) > raw_data_.size()) {
            return std::unexpected(parse_error::file_too_small);
        }

        T value;
        std::memcpy(&value, raw_data_.data() + offset, sizeof(T));
        return value;
    }

    template<typename T>
    std::expected<void, parse_error> pe_file::write_at_offset(size_t offset, const T& data) {
        if (offset + sizeof(T) > raw_data_.size()) {
            return std::unexpected(parse_error::file_too_small);
        }

        std::memcpy(raw_data_.data() + offset, &data, sizeof(T));
        return {};
    }

    template std::expected<dos_header_t, parse_error> pe_file::read_at_offset<dos_header_t>(size_t) const;
    template std::expected<pe_header_t, parse_error> pe_file::read_at_offset<pe_header_t>(size_t) const;
    template std::expected<optional_header_32_t, parse_error> pe_file::read_at_offset<optional_header_32_t>(size_t) const;
    template std::expected<optional_header_64_t, parse_error> pe_file::read_at_offset<optional_header_64_t>(size_t) const;
    template std::expected<section_header_t, parse_error> pe_file::read_at_offset<section_header_t>(size_t) const;
    template std::expected<uint16_t, parse_error> pe_file::read_at_offset<uint16_t>(size_t) const;
    template std::expected<uint32_t, parse_error> pe_file::read_at_offset<uint32_t>(size_t) const;

    template std::expected<void, parse_error> pe_file::write_at_offset<dos_header_t>(size_t, const dos_header_t&);
    template std::expected<void, parse_error> pe_file::write_at_offset<pe_header_t>(size_t, const pe_header_t&);
    template std::expected<void, parse_error> pe_file::write_at_offset<section_header_t>(size_t, const section_header_t&);
    template std::expected<void, parse_error> pe_file::write_at_offset<uint32_t>(size_t, const uint32_t&);

    std::string parse_error_to_string(parse_error error) {
        switch (error) {
        case parse_error::file_not_found:
            return "File not found";
        case parse_error::invalid_dos_header:
            return "Invalid DOS header";
        case parse_error::invalid_pe_header:
            return "Invalid PE header";
        case parse_error::invalid_optional_header:
            return "Invalid optional header";
        case parse_error::invalid_section_headers:
            return "Invalid section headers";
        case parse_error::unsupported_architecture:
            return "Unsupported architecture";
        case parse_error::file_too_small:
            return "File too small";
        case parse_error::corrupted_data:
            return "Corrupted data";
        default:
            return "Unknown error";
        }
    }

    std::string architecture_to_string(pe_file::architecture arch) {
        switch (arch) {
        case pe_file::architecture::x86:
            return "x86";
        case pe_file::architecture::x64:
            return "x64";
        case pe_file::architecture::unknown:
            return "unknown";
        default:
            return "invalid";
        }
    }

} // namespace quikpak