#include "fowarder.h"

uint32_t htonl(uint32_t hostlong) {
    uint32_t result = (hostlong >> 24) | ((hostlong & 0x00FF0000) >> 8) | ((hostlong & 0x0000FF00) << 8) | (hostlong << 24);
    return result;
}

uint32_t ntohl(uint32_t netlong) {
    return htonl(netlong);
}

uint16_t htons(uint16_t hostshort) {
    uint16_t result = (hostshort >> 8) | (hostshort << 8);
    return result;
}

uint16_t ntohs(uint16_t netshort) {
    return htons(netshort);
}

void PacketForwarder::add_data(int id, Protocol protocol, 
    uint32_t dest_address, uint16_t dest_port, std::shared_ptr<std::string> data) {
    // Criar o cabeçalho do pacote
    PacoteHeader header;
    header.protocol = static_cast<uint8_t>(protocol);
    header.dataSize = data->size();
    header.destAddress = htonl(dest_address);
    header.destPort = htons(dest_port);

    // Criar o pacote
    std::string pacote;
    pacote.resize(sizeof(PacoteHeader) + data->size());
    memcpy(&pacote[0], &header, sizeof(PacoteHeader));
    memcpy(&pacote[sizeof(PacoteHeader)], data->c_str(), data->size());

    // Enviar o pacote usando o gateway
    if (gateway_) {
        gateway_->add_data(std::make_shared<std::string>(pacote));
    }
    else {
        std::cout << "Gateway não configurado." << std::endl;
    }
}

void PacketForwarder::async_recv(std::function<void(int, uint32_t, uint16_t, 
    std::shared_ptr<std::string>)> handler) {
    // Configurar o callback para receber pacotes do gateway
    if (gateway_) {
        gateway_->async_recv([this, handler](int id, std::shared_ptr<std::string> pacote) {
            // Processar o pacote
            PacoteHeader* header = reinterpret_cast<PacoteHeader*>(const_cast<char*>(pacote->c_str()));
            uint32_t destAddress = ntohl(header->destAddress);
            uint16_t destPort = ntohs(header->destPort);
            std::shared_ptr<std::string> data = std::make_shared<std::string>(pacote->substr(sizeof(PacoteHeader)));

            // Chamar o callback com as informações necessárias
            handler(id, destAddress, destPort, data);
            });
    }
    else {
        std::cout << "Gateway não configurado." << std::endl;
    }
}
