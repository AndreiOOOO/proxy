#include "gateway_remote.h"



// ServerSession.cpp
ServerSession::ServerSession(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket)
    : io_context_(io_context),
    socket_(std::move(socket)) {}

ServerSession::~ServerSession() {}

void ServerSession::start() {
    buffer_.resize(1024);
    socket_.async_read_some(boost::asio::buffer(buffer_), std::bind(&ServerSession::handle_read, this, std::placeholders::_1, std::placeholders::_2));
}

void ServerSession::async_recv(std::function<void(std::shared_ptr<std::string>)> handler) {
    recv_handler_ = handler;
}

void ServerSession::add_data(std::shared_ptr<std::string> data) {
    write_queue_.push(data);
    if (!writing_) {
        writing_ = true;
        write_next();
    }
}

void ServerSession::close() {
    socket_.close();
}

void ServerSession::handle_read(const boost::system::error_code& error, size_t bytes_transferred) {
    if (!error) {
        std::shared_ptr<std::string> data = std::make_shared<std::string>(buffer_.data(), bytes_transferred);
        if (recv_handler_) {
            recv_handler_(data);
        }
        socket_.async_read_some(boost::asio::buffer(buffer_), std::bind(&ServerSession::handle_read, this, std::placeholders::_1, std::placeholders::_2));
    }
    else {
        // Lidar com erro
    }
}

void ServerSession::write_next() {
    if (!write_queue_.empty()) {
        std::shared_ptr<std::string> data = write_queue_.front();
        write_queue_.pop();
        boost::asio::async_write(socket_, boost::asio::buffer(*data), std::bind(&ServerSession::handle_write, this, std::placeholders::_1));
    }
    else {
        writing_ = false;
    }
}

void ServerSession::handle_write(const boost::system::error_code& error) {
    if (error) {
        // Lidar com erro
    }
    else {
        write_next();
    }
}

// Server.cpp
Server::Server(boost::asio::io_context& io_context, unsigned short port)
    : io_context_(io_context),
    acceptor_(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)) {
    start_accept();
}

Server::~Server() {}

void Server::start_accept() {
    acceptor_.async_accept([this](const boost::system::error_code& error, boost::asio::ip::tcp::socket socket) {
        if (!error) {
            std::shared_ptr<ServerSession> session = std::make_shared<ServerSession>(io_context_, std::move(socket));
            int session_id = next_session_id_++;
            sessions_[session_id] = session;
            session->start();
            start_accept();
        }
        });
}

void Server::async_recv(int session_id, std::function<void(int, std::shared_ptr<std::string>)> handler) {
    auto session = sessions_.find(session_id);
    if (session != sessions_.end()) {
        session->second->async_recv([handler, session_id](std::shared_ptr<std::string> data) {
            handler(session_id, data);
            });
    }
    else {
        io_context_.post([handler, session_id]() {
            handler(session_id, std::make_shared<std::string>());
            });
    }
}

void Server::add_data(int session_id, std::shared_ptr<std::string> data) {
    auto session = sessions_.find(session_id);
    if (session != sessions_.end()) {
        session->second->add_data(data);
    }
}

void Server::close_session(int session_id) {
    auto session = sessions_.find(session_id);
    if (session != sessions_.end()) {
        session->second->close();
        sessions_.erase(session);
    }
}