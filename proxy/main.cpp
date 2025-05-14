#define _CRT_SECURE_NO_WARNINGS

#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include "ip_convert.h"

// Funções de verificação de privilégios e obtenção de diretório atual
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

// Declarações de funções externas
extern void set_udp_server_endpoint(DWORD addr, WORD port);
extern void set_tcp_server_endpoint(DWORD addr, WORD port);
extern int run_windivert();

extern void core_run(boost::asio::io_context* io_context_);
extern void filter_any_server_init(boost::asio::io_context& io_context, unsigned short tcp_port, unsigned short udp_port);

extern void internet_connector_init(boost::asio::io_context& io_context);
extern void gateway_init(boost::asio::io_context* io_context);

// Variáveis globais
boost::asio::io_context io_context;
uint16_t tcp_server_port = 1001;
uint16_t udp_server_port = 1002;

// Função para executar o WinDivert
void run_divert() {
    std::thread(run_windivert).detach();
}

//used on core if testing
void init_internet_connector_on_main() {
    internet_connector_init(io_context);
}

// Função de inicialização
void init() {
    uint32_t address = ip_to_uint32("192.168.1.105");
    set_tcp_server_endpoint(address, tcp_server_port);
    set_udp_server_endpoint(address, udp_server_port);
    run_divert();

    filter_any_server_init(io_context, tcp_server_port, udp_server_port);
    gateway_init(&io_context);

    boost::asio::io_context* io_ptr = &io_context;
    io_context.post(
        [io_ptr]() { 
            core_run(io_ptr); 
        }
    );
}

// Função para executar o io_context
void run() {
    io_context.run();
}

int main() {
    // Desabilita a saída de stdout
   // freopen("NUL", "w", stdout);

    // Verifica se o programa está sendo executado com privilégios de administrador
    if (!isAdmin()) {
        MessageBox(NULL, "O programa precisa ser executado com privilégios de administrador.", "Erro", MB_ICONERROR);
        return 1;
    }

    init();

    while (true) {
        run();
    }

    return 0;
}