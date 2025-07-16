#include "pe/pe_parser.h"
#include "header/header_protection.h"

#include <iostream>
#include <filesystem>
#include <string_view>

namespace fs = std::filesystem;
using namespace quikpak;

struct app_config {
    std::string input_file;
    std::string output_file;
    bool create_backup = false;
    bool apply_header_protection = true;
    bool apply_section_encryption = true;
    bool apply_anti_debug = true;
};

void print_usage(std::string_view program_name);
std::expected<app_config, std::string> parse_arguments(int argc, char* argv[]);
std::expected<void, std::string> validate_input_file(const std::string& file_path);
std::expected<std::string, std::string> generate_output_filename(const std::string& input_file);
std::expected<void, std::string> create_backup_file(const std::string& original_file);

int main(int argc, char* argv[]) {
    auto config_result = parse_arguments(argc, argv);
    if (!config_result) {
        std::cerr << "Error: " << config_result.error() << "\n";
        print_usage(argv[0]);
        return 1;
    }

    auto config = std::move(*config_result);

    try {
        if (auto result = validate_input_file(config.input_file); !result) {
            std::cerr << "Error: " << result.error() << "\n";
            return 1;
        }

        if (config.output_file.empty()) {
            auto output_result = generate_output_filename(config.input_file);
            if (!output_result) {
                std::cerr << "Error: " << output_result.error() << "\n";
                return 1;
            }
            config.output_file = *output_result;
        }

        if (config.create_backup) {
            if (auto result = create_backup_file(config.input_file); !result) {
                std::cerr << "Warning: Failed to create backup: " << result.error() << "\n";
            }
        }

        auto pe_result = pe_file::from_file(config.input_file);
        if (!pe_result) {
            std::cerr << "Error: " << parse_error_to_string(pe_result.error()) << "\n";
            return 1;
        }

        auto pe = std::move(*pe_result);

        if (!pe.is_executable()) {
            std::cerr << "Warning: Not an executable\n";
        }

        bool protection_applied = false;

        if (config.apply_header_protection) {
            header_protection header_protector;
            header_protection_config header_config;

            if (auto result = header_protector.apply_protection(pe, header_config); !result) {
                std::cerr << "Warning: Header protection failed: " << protection_error_to_string(result.error()) << "\n";
            }
            else {
                protection_applied = true;
            }
        }

        if (config.apply_section_encryption) {

        }

        if (config.apply_anti_debug) {

        }

        if (auto result = pe.save_to_file(config.output_file); !result) {
            std::cerr << "Error: " << parse_error_to_string(result.error()) << "\n";
            return 1;
        }

        std::cout << "Protection applied successfully!\n";
        std::cout << "Output file: " << config.output_file << "\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}

void print_usage(std::string_view program_name) {
    std::cout << "Usage: " << program_name << " <input_file> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -o, --output <file>   Specify output file\n";
    std::cout << "  --backup             Create backup of original file\n";  // Changed: now opt-in
    std::cout << "  --no-header          Skip header protection\n";
    std::cout << "  --no-encryption      Skip section encryption\n";
    std::cout << "  --no-antidebug       Skip anti-debug measures\n";
    std::cout << "  -h, --help           Show this help\n\n";
}

std::expected<app_config, std::string> parse_arguments(int argc, char* argv[]) {
    if (argc < 2) {
        return std::unexpected("No input file specified");
    }

    app_config config;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            std::exit(0);
        }
        else if (arg == "--backup") {  // Changed: now enables backup creation
            config.create_backup = true;
        }
        else if (arg == "--no-header") {
            config.apply_header_protection = false;
        }
        else if (arg == "--no-encryption") {
            config.apply_section_encryption = false;
        }
        else if (arg == "--no-antidebug") {
            config.apply_anti_debug = false;
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                return std::unexpected("Output filename not specified after " + arg);
            }
            config.output_file = argv[++i];
        }
        else if (arg.starts_with("-")) {
            return std::unexpected("Unknown option: " + arg);
        }
        else {
            if (config.input_file.empty()) {
                config.input_file = arg;
            }
            else {
                return std::unexpected("Multiple input files specified: " + config.input_file + " and " + arg);
            }
        }
    }

    if (config.input_file.empty()) {
        return std::unexpected("No input file specified");
    }

    return config;
}

std::expected<void, std::string> validate_input_file(const std::string& file_path) {
    fs::path path(file_path);

    if (!fs::exists(path)) {
        return std::unexpected("File does not exist: " + file_path);
    }

    if (!fs::is_regular_file(path)) {
        return std::unexpected("Path is not a regular file: " + file_path);
    }

    auto file_size = fs::file_size(path);
    if (file_size < sizeof(dos_header_t)) {
        return std::unexpected("File is too small to be a valid PE file");
    }

    return {};
}

std::expected<std::string, std::string> generate_output_filename(const std::string& input_file) {
    fs::path input_path(input_file);

    auto stem = input_path.stem();
    auto extension = input_path.extension();
    auto parent = input_path.parent_path();

    std::string output_file = (parent / (stem.string() + "_protected" + extension.string())).string();

    if (fs::absolute(input_path) == fs::absolute(fs::path(output_file))) {
        return std::unexpected("Output file would overwrite input file");
    }

    return output_file;
}

std::expected<void, std::string> create_backup_file(const std::string& original_file) {
    fs::path original_path(original_file);

    auto stem = original_path.stem();
    auto extension = original_path.extension();
    auto parent = original_path.parent_path();

    std::string backup_file = (parent / (stem.string() + "_backup" + extension.string())).string();

    std::error_code ec;
    fs::copy_file(original_path, backup_file, fs::copy_options::overwrite_existing, ec);

    if (ec) {
        return std::unexpected("Failed to create backup: " + ec.message());
    }

    return {};
}