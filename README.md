# QuikPak

Windows PE protection tool written in C++.

## Status
This project is abandoned, and was a representation of my abilities as a novice reverse engineer.
## Usage

```bash
quikpak.exe input.exe [options]
```

Options:
- `-o, --output <file>` - Custom output file
- `--backup` - Create backup of original file
- `--no-header` - Skip header protection
- `-h, --help` - Show help

Example:
```bash
quikpak.exe myapp.exe --backup
```

## Build

Requires Visual Studio 2019+ with C++20 support.

## License
[MIT](https://opensource.org/license/mit)
> QuikPak is not recommended to be used in a commercial context, see code before use.
