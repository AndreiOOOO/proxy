#ifndef SERVER_FORWARDER_H
#define SERVER_FORWARDER_H

#include <boost/asio.hpp>
#include <map>
#include <memory>
#include <string>

#include "gateway_remote.h"

// Enum para os protocolos
enum class Protocol {
    TCP,
    UDP,
    // Outros protocolos...
};

// Estrutura para representar um pacote
struct Packet {
    int id;
    Protocol protocol;
    uint32_t destinationAddress;
    uint16_t destinationPort;
    std::shared_ptr<std::string> data;

    Packet(std::shared_ptr<std::string> data) {
        // Implementação da deserialização do pacote
        // ...
    }

    Protocol getProtocol() {
        return protocol;
    }

    int getId() {
        return id;
    }

    uint32_t getDestinationAddress() {
        return destinationAddress;
    }

    uint16_t getDestinationPort() {
        return destinationPort;
    }

    std::shared_ptr<std::string> getData() {
        return data;
    }
};

// Interface para os injectors
class Injector {
public:
    virtual void send(int injectorId, uint32_t destinationAddress, uint16_t destinationPort, std::shared_ptr<std::string> data) = 0;
    virtual void async_recv(std::function<void(int, std::shared_ptr<std::string>)> handler) = 0;
};

// Classe para o forwarder server-side
class ServerForwarder {
public:
    ServerForwarder(Server* gateway) : gateway_(gateway) {}

    void start();

    void registerInjector(Protocol protocol, std::shared_ptr<Injector> injector);

    int createInjectorId(int sessionId, int packetId);

    void handleRecv(int sessionId, std::shared_ptr<std::string> data);

    void handleInjectorData(int injectorId, std::shared_ptr<std::string> data);

private:
    Server* gateway_;
    std::map<Protocol, std::shared_ptr<Injector>> injectors_;
};

#endif // SERVER_FORWARDER_H
