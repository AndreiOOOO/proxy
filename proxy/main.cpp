

#include <boost/asio.hpp>
#include <iostream>
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

extern void core_run();
extern void filter_any_server_init(boost::asio::io_context& io_context, unsigned short tcp_port, unsigned short udp_port);


extern void internet_connector_init(boost::asio::io_context& io_context);
extern void gateway_init(boost::asio::io_context* io_context);


boost::asio::io_context io_context;

uint16_t tcp_server_port = 1001;
uint16_t udp_server_port = 1002;

void run_divert() {
    std::thread(run_windivert).detach();
}

void init() {
    uint32_t address = ip_to_uint32("192.168.1.105");
    set_tcp_server_endpoint(address, tcp_server_port);
    set_udp_server_endpoint(address, udp_server_port);
    run_divert();

    filter_any_server_init(io_context, tcp_server_port, udp_server_port);
    internet_connector_init(io_context);

    gateway_init(&io_context);

    io_context.post(
        []() {core_run(); }
    );
}


void run() {
    io_context.run();
}

int main()
{
    std::cout << getCurrentDirectory();

    if (!isAdmin()) {
        MessageBox(NULL, "O programa precisa ser executado com privilégios de administrador.", "Erro", MB_ICONERROR);
        return 1;
    }

    init();
    while (true) {
        run();
    }
}
