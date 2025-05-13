#pragma once


#include <iostream>

static uint32_t ip_string_to_dword(const std::string& ip_str) {
    uint32_t ip = 0;
    size_t pos = 0;
    for (int i = 0; i < 4; i++) {
        size_t next_pos = ip_str.find('.', pos);
        if (next_pos == std::string::npos && i < 3) {
            throw std::invalid_argument("Invalid IP address format");
        }
        uint32_t octet = std::stoi(ip_str.substr(pos, next_pos - pos));
        if (octet > 255) {
            throw std::invalid_argument("Invalid IP address octet");
        }
        ip |= octet << (24 - i * 8);
        pos = next_pos + 1;
    }
    return ip;
}


static uint32_t ip_to_uint32(const std::string& ip) {
    return ip_string_to_dword(ip);
    std::istringstream iss(ip);
    uint32_t result = 0;
    uint8_t a, b, c, d;
    char dot;
    if (iss >> a >> dot >> b >> dot >> c >> dot >> d && dot == '.') {
        result = (a << 24) | (b << 16) | (c << 8) | d;
    }
    return result;
}