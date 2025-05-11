#include <wpp/thread/thread.hpp>
#include <iostream>

uint32_t ip_string_to_dword(const std::string& ip_str) {
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


uint32_t ip_to_uint32(const std::string& ip) {
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


bool isAdmin() {
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            CloseHandle(hToken);
            return Elevation.TokenIsElevated != 0;
        }
    }
    return false;
}

std::string getCurrentDirectory() {
    char buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buffer);
    return std::string(buffer);
}


extern void set_udp_server_endpoint(DWORD addr, WORD port);
extern void set_tcp_server_endpoint(DWORD addr, WORD port);
extern int run_windivert();

int main()
{
    std::cout << getCurrentDirectory();

    if (!isAdmin()) {
        MessageBox(NULL, "O programa precisa ser executado com privilégios de administrador.", "Erro", MB_ICONERROR);
        return 1;
    }
    
    uint32_t address = ip_to_uint32("127.0.0.1");
    set_tcp_server_endpoint(address, 1001);
    set_udp_server_endpoint(address, 1002);
    run_windivert();

    while (true) {
        wpp::thread::current::sleep(200);
    }
}
