#include <iostream>
#include <string>
#include <memory>
#include <functional>


enum class Protocol { TCP, UDP };

struct PacoteHeader {
    uint8_t protocol; // Protocolo (TCP ou UDP)
    uint16_t dataSize; // Tamanho do dado
    uint32_t destAddress; // Endereço de destino (IP)
    uint16_t destPort; // Porta de destino
};

class IGateway {
public:
    virtual void add_data(std::shared_ptr<std::string> data) = 0;
    virtual void async_recv(std::function<void(int, std::shared_ptr<std::string>)> handler) = 0;
};

class PacketForwarder {
public:
    PacketForwarder(std::shared_ptr<IGateway> gateway) : gateway_(gateway) {}

    void add_data(int id, Protocol protocol, uint32_t dest_address,
        uint16_t dest_port, std::shared_ptr<std::string> data);

    void async_recv(std::function<void(int, uint32_t, uint16_t,
        std::shared_ptr<std::string>)> handler);

private:
    std::shared_ptr<IGateway> gateway_;
};
