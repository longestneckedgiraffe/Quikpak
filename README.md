# QuikPak

Windows PE protection tool written in C++.

## Status
Several unfinished protection features in current state.
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
> QuikPak is not meant to be used as a legitmiate protection software.
