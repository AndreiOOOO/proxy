#include "udp.h"

void UDPInjector::send(int id, uint32_t destAddress, uint16_t destPort, std::shared_ptr<std::string> data) {
    if (sockets_.find(id) == sockets_.end()) {
        sockets_[id] = std::make_shared<boost::asio::ip::udp::socket>(io_service_);
        sockets_[id]->open(boost::asio::ip::udp::v4());
    }

    boost::asio::ip::udp::endpoint endpoint(boost::asio::ip::address_v4(destAddress), destPort);
    sockets_[id]->async_send_to(boost::asio::buffer(*data), endpoint, boost::bind(&UDPInjector::handleSend, this, id, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}

void UDPInjector::async_recv(std::function<void(int, std::shared_ptr<std::string>)> handler) {
    if (!handler) {
        // Tratar erro de handler não definido
        return;
    }
    handler_ = handler;

    for (auto& pair : sockets_) {
        startRecv(pair.first);
    }
}

void UDPInjector::handleSend(int id, const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        // Tratar erro de envio
    }
}

void UDPInjector::startRecv(int id) {
    auto it = sockets_.find(id);
    if (it != sockets_.end()) {
        it->second->async_receive_from(boost::asio::buffer(recvBuffers_[id]), remoteEndpoints_[id], boost::bind(&UDPInjector::handleRecv, this, id, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
    }
}

void UDPInjector::handleRecv(int id, const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        // Tratar erro de recebimento
    }
    else {
        std::shared_ptr<std::string> data = std::make_shared<std::string>(recvBuffers_[id].begin(), recvBuffers_[id].begin() + bytes_transferred);
        handler_(id, data);
        startRecv(id);
    }
}
