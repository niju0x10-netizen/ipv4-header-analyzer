#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using Byte = std::uint8_t;

std::uint16_t read16(const std::vector<Byte>& data, std::size_t pos) {
    return static_cast<std::uint16_t>((static_cast<unsigned>(data[pos]) << 8) | data[pos + 1]);
}

bool parseHex(const std::string& line, std::vector<Byte>& bytes, std::string& error) {
    std::istringstream input(line);
    std::string token;
    while (input >> token) {
        if (token.size() != 2) {
            error = "Each byte must contain exactly two hexadecimal digits (example: 0A).";
            return false;
        }
        unsigned value = 0;
        for (char c : token) {
            unsigned digit;
            if (c >= '0' && c <= '9') digit = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') digit = static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') digit = static_cast<unsigned>(c - 'A' + 10);
            else {
                error = "Invalid hexadecimal byte: " + token;
                return false;
            }
            value = value * 16 + digit;
        }
        bytes.push_back(static_cast<Byte>(value));
    }
    if (bytes.empty()) {
        error = "No bytes were provided.";
        return false;
    }
    return true;
}

bool validChecksum(const std::vector<Byte>& data, std::size_t headerLength) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < headerLength; i += 2) {
        sum += read16(data, i);
        while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return sum == 0xFFFFu;
}

std::string protocolName(unsigned protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "Other";
    }
}

void printIp(const std::vector<Byte>& data, std::size_t pos) {
    for (std::size_t i = 0; i < 4; ++i) {
        if (i) std::cout << '.';
        std::cout << static_cast<unsigned>(data[pos + i]);
    }
}

int main() {
    std::cout << "IPv4 Header Analyzer\n"
              << "Enter hexadecimal bytes separated by spaces.\n"
              << "Example: 45 00 00 3C ...\n> ";
    std::string line;
    if (!std::getline(std::cin, line)) return 1;

    std::vector<Byte> data;
    std::string error;
    if (!parseHex(line, data, error)) {
        std::cerr << "Input error: " << error << '\n';
        return 1;
    }
    if (data.size() < 20) {
        std::cerr << "Invalid IPv4 header: at least 20 bytes are required.\n";
        return 1;
    }

    unsigned version = data[0] >> 4;
    unsigned ihl = data[0] & 0x0Fu;
    std::size_t headerLength = ihl * 4u;
    if (version != 4 || ihl < 5 || headerLength > 60 || data.size() < headerLength) {
        std::cerr << "Invalid IPv4 header: check Version, IHL, and supplied bytes.\n";
        return 1;
    }

    unsigned totalLength = read16(data, 2);
    if (totalLength < headerLength) {
        std::cerr << "Invalid IPv4 header: Total Length is smaller than Header Length.\n";
        return 1;
    }

    unsigned identification = read16(data, 4);
    unsigned flagsOffset = read16(data, 6);
    unsigned reserved = (flagsOffset >> 15) & 1u;
    unsigned df = (flagsOffset >> 14) & 1u;
    unsigned mf = (flagsOffset >> 13) & 1u;
    unsigned offset = flagsOffset & 0x1FFFu;
    unsigned checksum = read16(data, 10);

    std::cout << "\n=== IPv4 Header ===\n";
    std::cout << "Version: " << version << '\n';
    std::cout << "IHL: " << ihl << " (" << headerLength << " bytes)\n";
    std::cout << "ToS / DS Field: " << static_cast<unsigned>(data[1]) << '\n';
    std::cout << "DSCP: " << (data[1] >> 2) << '\n';
    std::cout << "ECN: " << (data[1] & 3u) << '\n';
    std::cout << "Total Length: " << totalLength << " bytes\n";
    std::cout << "IP Payload Length: " << totalLength - headerLength << " bytes\n";
    std::cout << "Identification: " << identification << '\n';
    std::cout << "Reserved Flag: " << reserved << '\n';
    std::cout << "DF: " << df << '\n';
    std::cout << "MF: " << mf << '\n';
    std::cout << "Fragment Offset: " << offset << " (" << offset * 8u << " bytes)\n";
    std::cout << "Fragmented: " << ((mf || offset) ? "Yes" : "No") << '\n';
    std::cout << "TTL: " << static_cast<unsigned>(data[8]) << '\n';
    std::cout << "Protocol: " << protocolName(data[9]) << " (" << static_cast<unsigned>(data[9]) << ")\n";
    std::cout << "Header Checksum: 0x" << std::uppercase << std::hex
              << std::setw(4) << std::setfill('0') << checksum << std::dec << '\n';
    std::cout << "Header Checksum Valid: " << (validChecksum(data, headerLength) ? "Yes" : "No") << '\n';
    std::cout << "Source IP: "; printIp(data, 12); std::cout << '\n';
    std::cout << "Destination IP: "; printIp(data, 16); std::cout << '\n';

    if (headerLength > 20) {
        std::cout << "Options/Padding raw bytes:";
        for (std::size_t i = 20; i < headerLength; ++i) {
            std::cout << ' ' << std::uppercase << std::hex << std::setw(2)
                      << std::setfill('0') << static_cast<unsigned>(data[i]);
        }
        std::cout << std::dec << '\n';
    } else {
        std::cout << "Options/Padding: None\n";
    }
    if (data.size() < totalLength) {
        std::cout << "Note: only " << data.size()
                  << " bytes supplied; Total Length describes " << totalLength
                  << " bytes. This can be a header-only input.\n";
    } else if (data.size() > totalLength) {
        std::cout << "Note: input contains bytes beyond the IPv4 Total Length.\n";
    }
    if (reserved || (df && (mf || offset))) {
        std::cout << "Warning: unusual/inconsistent fragmentation flags.\n";
    }
    return 0;
}
