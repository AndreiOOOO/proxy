#include "fowarder_server.h"

void ServerForwarder::start() {
    gateway_->async_recv(
        -1,
        [this](int sessionId, std::shared_ptr<std::string> data) {
        handleRecv(sessionId, data);
        }
    );
}

void ServerForwarder::registerInjector(Protocol protocol, std::shared_ptr<Injector> injector) {
    injectors_[protocol] = injector;
    injector->async_recv([this](int injectorId, std::shared_ptr<std::string> data) {
        handleInjectorData(injectorId, data);
        });
}

int ServerForwarder::createInjectorId(int sessionId, int packetId) {
    return (sessionId << 16) | packetId;
}

void ServerForwarder::handleRecv(int sessionId, std::shared_ptr<std::string> data) {
    Packet packet(data);
    Protocol protocol = packet.getProtocol();
    int injectorId = createInjectorId(sessionId, packet.getId());
    if (injectors_.find(protocol) != injectors_.end()) {
        injectors_[protocol]->send(injectorId, packet.getDestinationAddress(), packet.getDestinationPort(), packet.getData());
    }
}

void ServerForwarder::handleInjectorData(int injectorId, std::shared_ptr<std::string> data) {
    int sessionId = injectorId >> 16;
    gateway_->add_data(sessionId, data);
}
