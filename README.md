# IPv4 Header Analyzer (C++)

A command-line tool that parses user-supplied IPv4 header bytes and prints all core IPv4 fields, including fragmentation flags and checksum validation.

## Requirements

- C++17 compiler (g++, clang++, or MSVC)

## Build

```bash
g++ -std=c++17 -Wall -Wextra -pedantic main.cpp -o ipv4-analyzer
```

On Windows with MinGW, use `-o ipv4-analyzer.exe`.

## Run

```bash
./ipv4-analyzer
```

Paste space-separated hexadecimal bytes, **exactly two digits per byte**:

```text
45 00 00 3C 12 34 00 00 40 06 96 C6 C0 A8 01 0A 08 08 08 08
```

The sample is a **20-byte IPv4 header only** with a declared IP Total Length of 60 bytes. The checksum is valid for the provided header. The program can also accept a full packet, but it analyzes only the IPv4 header.

## Features

- IPv4 version and header-length validation
- DSCP / ECN
- Total Length and IP payload length
- Identification, reserved/DF/MF flags, Fragment Offset and byte position
- TTL and protocol identification
- IPv4 header checksum verification (ones' complement)
- Source and destination IPv4 addresses
- Raw options/padding bytes when IHL exceeds 5
- Input errors and warnings for inconsistent fields

## Notes

- Input begins at the **IPv4 header**, not an Ethernet header.
- `Fragment Offset` is expressed in units of 8 bytes; `IHL` is in units of 4 bytes.
- Checksum validation covers only the IPv4 header, not the payload.
- Raw Options/Padding are shown but individual option types are not decoded.
- The tool is for education and header inspection, not a complete packet capture or IDS.

## License

MIT (see LICENSE).
