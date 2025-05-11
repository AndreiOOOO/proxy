
#include "tcp.h"

void TCPInjector::send(int id, uint32_t destAddress, uint16_t destPort, std::shared_ptr<std::string> data) {
    // Criar um novo socket se necessário
    if (sockets_.find(id) == sockets_.end()) {
        sockets_[id] = std::make_shared<SocketState>();
        sockets_[id]->socket = std::make_shared<boost::asio::ip::tcp::socket>(io_service_);

        // Conectar ao destino
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address_v4(destAddress), destPort);
        sockets_[id]->socket->async_connect(endpoint, boost::bind(&TCPInjector::handleConnect, this, id, boost::asio::placeholders::error));
    }

    // Adicionar o pacote à fila de envio
    sockets_[id]->sendQueue.push(data);

    // Se o socket estiver conectado, enviar o pacote
    if (sockets_[id]->connected) {
        sendNextPacket(id);
    }
}

void TCPInjector::async_recv(std::function<void(int, std::shared_ptr<std::string>)> handler) {
    if (!handler) {
        // Tratar erro de handler não definido
        return;
    }
    handler_ = handler;

    // Iniciar a recepção de pacotes para cada socket conectado
    for (auto& pair : sockets_) {
        if (pair.second->connected) {
            startRecv(pair.first);
        }
    }
}


void TCPInjector::handleConnect(int id, const boost::system::error_code& error) {
    if (error) {
        // Tratar erro de conexão
    }
    else {
        sockets_[id]->connected = true;
        sendNextPacket(id);
        if (handler_) {
            startRecv(id);
        }
    }
}

void TCPInjector::sendNextPacket(int id) {
    if (!sockets_[id]->sendQueue.empty()) {
        std::shared_ptr<std::string> data = sockets_[id]->sendQueue.front();
        sockets_[id]->sendQueue.pop();

        boost::asio::async_write(*sockets_[id]->socket, boost::asio::buffer(*data), boost::bind(&TCPInjector::handleWrite, this, id, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
    }
}

void TCPInjector::handleWrite(int id, const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        // Tratar erro de escrita
    }
    else {
        sendNextPacket(id);
    }
}

void TCPInjector::startRecv(int id) {
    auto it = sockets_.find(id);
    if (it != sockets_.end() && it->second->connected && !it->second->receiving) {
        it->second->receiving = true;
        boost::asio::async_read(*it->second->socket, boost::asio::buffer(*it->second->recvBuffer), boost::bind(&TCPInjector::handleRecv, this, id, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
    }
}

void TCPInjector::handleRecv(int id, const boost::system::error_code& error, size_t bytes_transferred) {
    auto it = sockets_.find(id);
    if (it != sockets_.end()) {
        it->second->receiving = false;

        if (error) {
            // Socket fechado ou erro
            handler_(id, std::make_shared<std::string>());
        }
        else {
            it->second->recvBuffer->resize(bytes_transferred);
            handler_(id, it->second->recvBuffer);
            it->second->recvBuffer = std::make_shared<std::string>();
            it->second->recvBuffer->resize((uint16_t)-1);
            // Continuar recebendo pacotes
            startRecv(id);
        }
    }
}

