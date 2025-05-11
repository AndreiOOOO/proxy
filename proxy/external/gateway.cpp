#include "gateway.h"

// ClientSession.cpp
ClientSession::ClientSession(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket)
    : io_context_(io_context),
    socket_(std::move(socket)) {}

ClientSession::~ClientSession() {}

void ClientSession::start() {
    buffer_.resize(1024);
    socket_.async_read_some(boost::asio::buffer(buffer_), std::bind(&ClientSession::handle_read, this, std::placeholders::_1, std::placeholders::_2));
}

void ClientSession::async_recv(std::function<void(std::shared_ptr<std::string>)> handler) {
    recv_handler_ = handler;
}

void ClientSession::add_data(std::shared_ptr<std::string> data) {
    write_queue_.push(data);
    if (!writing_) {
        writing_ = true;
        write_next();
    }
}

void ClientSession::close() {
    socket_.close();
}

void ClientSession::handle_read(const boost::system::error_code& error, size_t bytes_transferred) {
    if (!error) {
        std::shared_ptr<std::string> data = std::make_shared<std::string>(buffer_.data(), bytes_transferred);
        if (recv_handler_) {
            recv_handler_(data);
        }
        socket_.async_read_some(boost::asio::buffer(buffer_), std::bind(&ClientSession::handle_read, this, std::placeholders::_1, std::placeholders::_2));
    }
    else {
        // Lidar com erro
    }
}

void ClientSession::write_next() {
    if (!write_queue_.empty()) {
        std::shared_ptr<std::string> data = write_queue_.front();
        write_queue_.pop();
        boost::asio::async_write(socket_, boost::asio::buffer(*data), std::bind(&ClientSession::handle_write, this, std::placeholders::_1));
    }
    else {
        writing_ = false;
    }
}

void ClientSession::handle_write(const boost::system::error_code& error) {
    if (error) {
        // Lidar com erro
    }
    else {
        write_next();
    }
}


// ClientGateway.cpp
ClientGateway::ClientGateway(boost::asio::io_context& io_context)
    : io_context_(io_context) {}

ClientGateway::~ClientGateway() {}

void ClientGateway::connect(const std::string& host, unsigned short port) {
    boost::asio::ip::tcp::resolver resolver(io_context_);
    boost::asio::ip::tcp::resolver::query query(host, std::to_string(port));
    boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
    boost::asio::ip::tcp::socket socket(io_context_);
    boost::asio::connect(socket, iterator);
    session_ = std::make_shared<ClientSession>(io_context_, std::move(socket));
    session_->start();
}

void ClientGateway::async_recv(std::function<void(int, std::shared_ptr<std::string>)> handler) {
    session_->async_recv([handler](std::shared_ptr<std::string> data) {
        handler(0, data);
        });
}

void ClientGateway::add_data(std::shared_ptr<std::string> data) {
    session_->add_data(data);
}

void ClientGateway::close() {
    session_->close();
}