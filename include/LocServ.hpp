#ifndef LOCSERV_HPP
#define LOCSERV_HPP
#include "Types.hpp"
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <mutex>
#include <unordered_map>
#include <thread>
#include <bit>
#include <iostream>

namespace conclave {

    class LocServ {
        private:
            static constexpr int BACKLOG = 10, MAX_EVENTS = 20;
            sockaddr_in address[2]; // 0 - public | 1 - private
            int event_manager = epoll_create1(0);
            int socket_descriptor[2] = {-1, -1};
            int private_fd = -1;

            std::unordered_map<ID, FDESC> users;
            std::unordered_map<FDESC, ID> _users;
            std::unordered_map<ID, Room> rooms;
            std::unordered_map<ID, ID> user2room;
            std::mutex add_user;

            inline ID generate_new_uid() noexcept {
                ID id = random();
                while (users.find(id) != users.end()) id = random();
                return id;
            }

            inline ID generate_new_roomID() noexcept {
                ID id = random();
                while (rooms.find(id) != rooms.end()) id = random();
                return id;
            }

            // Safely remove fd from epoll and close it
            void close_fd(int fd) {
                epoll_ctl(event_manager, EPOLL_CTL_DEL, fd, nullptr);
                close(fd);
            }

            void send_room_list(int fd) {
                if (fd < 0) return;
                std::vector<uint8_t> data;
                data.push_back(static_cast<uint8_t>(MessageType::ROOM_LIST));

                for (const auto &[id, room] : rooms) {
                    uint32_t network_id = htonl(id);
                    data.insert(data.end(), reinterpret_cast<uint8_t*>(&network_id),
                                           reinterpret_cast<uint8_t*>(&network_id) + 4);
                    data.push_back(static_cast<uint8_t>(room.name.length()));
                    data.insert(data.end(), room.name.begin(), room.name.end());
                }

                send_message_fd(fd, data);
            }

            template<bool Private>
            void accept_new_connection() {
                sockaddr_in addr;
                socklen_t len = sizeof(addr);

                int master_fd = Private ? socket_descriptor[1] : socket_descriptor[0];
                int new_fd = accept(master_fd, (sockaddr*)&addr, &len);

                if (new_fd < 0) return;

                // Use level-triggered EPOLLIN only — simpler and correct for our
                // blocking-style read loop. EPOLLET requires full drain on every
                // wakeup, which conflicts with read_message's incremental reads.
                fcntl(new_fd, F_SETFL, O_NONBLOCK);
                epoll_event event{};
                event.events = EPOLLIN;
                event.data.fd = new_fd;

                if (epoll_ctl(event_manager, EPOLL_CTL_ADD, new_fd, &event) == -1) {
                    close(new_fd);
                    return;
                }

                std::lock_guard<std::mutex> lock(add_user);
                if constexpr (Private) {
                    private_fd = new_fd;
                    std::cout << "[CONTROL] Python Bridge linked on FD " << new_fd << std::endl;
                    send_room_list(new_fd);
                } else {
                    ID uid = generate_new_uid();
                    users.emplace(uid, new_fd);
                    _users.emplace(new_fd, uid);
                    std::cout << "[DATA] User linked on FD " << new_fd << " (UID: " << uid << ")" << std::endl;
                }
            }

            // Reads exactly `n` bytes from fd, handling EAGAIN on non-blocking fds.
            // Returns false if the connection is closed or an unrecoverable error occurs.
            bool read_exact(int fd, uint8_t* dst, size_t n) {
                size_t read_len = 0;
                while (read_len < n) {
                    ssize_t curr = read(fd, dst + read_len, n - read_len);
                    if (curr > 0) {
                        read_len += curr;
                    } else if (curr == 0) {
                        // Peer closed connection cleanly
                        return false;
                    } else {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            // No data available yet — yield and retry
                            // (epoll will wake us again when data arrives,
                            //  but we are already inside the handler so just spin briefly)
                            continue;
                        }
                        return false;
                    }
                }
                return true;
            }

            void read_message(int fd, SecureBuffer<uint8_t>& buffer) {
                uint32_t size = 0;
                if (!read_exact(fd, reinterpret_cast<uint8_t*>(&size), sizeof(uint32_t)))
                    throw std::runtime_error("Connection closed reading size from fd " + std::to_string(fd));

                size = ntohl(size);
                if (size == 0 || size > 4 * 1024 * 1024) // Sanity cap: 4 MB
                    throw std::runtime_error("Invalid message size " + std::to_string(size));

                buffer.resize(size);
                if (!read_exact(fd, buffer.data(), size))
                    throw std::runtime_error("Connection closed reading body from fd " + std::to_string(fd));
            }

            void end_connection(ID uid) {
                FDESC fd = users.at(uid);
                if (user2room.contains(uid)) {
                    ID rid = user2room[uid];
                    rooms.at(rid).users.erase(uid);
                    user2room.erase(uid);
                    if (rooms.at(rid).users.empty()) rooms.erase(rid);
                }
                _users.erase(fd);
                users.erase(uid);
                close_fd(fd);
            }

            void end_connectionFD(FDESC fd) {
                auto it = _users.find(fd);
                if (it == _users.end()) {
                    // Unknown fd (e.g. private bridge) — just close cleanly
                    close_fd(fd);
                    return;
                }
                ID uid = it->second;
                _users.erase(it);
                if (user2room.contains(uid)) {
                    ID rid = user2room[uid];
                    rooms.at(rid).users.erase(uid);
                    user2room.erase(uid);
                    if (rooms.at(rid).users.empty()) rooms.erase(rid);
                }
                users.erase(uid);
                close_fd(fd);
            }

            void execute_command(SecureBuffer<uint8_t>& cmd) {
                if (cmd.empty()) return;
                Commands command = static_cast<Commands>(cmd.front());

                switch (command) {
                    case Commands::JOIN: {
                        // Expect: [CMD(1)] [room_id(4)] [user_id(4)]
                        if (cmd.size() < 1 + sizeof(ID) + sizeof(ID)) return;
                        ID target_room, target_user;
                        memcpy(&target_room, cmd.data() + 1, sizeof(ID));
                        memcpy(&target_user,  cmd.data() + 1 + sizeof(ID), sizeof(ID));
                        target_room = ntohl(target_room);
                        target_user = ntohl(target_user);
                        if (!rooms.contains(target_room)) return;
                        rooms.at(target_room).users.emplace(target_user);
                        user2room[target_user] = target_room;
                    } break;

                    case Commands::LEAVE: {
                        // Expect: [CMD(1)] [room_id(4)] [user_id(4)]
                        if (cmd.size() < 1 + sizeof(ID) + sizeof(ID)) return;
                        ID target_room, target_user;
                        memcpy(&target_room, cmd.data() + 1, sizeof(ID));
                        memcpy(&target_user,  cmd.data() + 1 + sizeof(ID), sizeof(ID));
                        target_room = ntohl(target_room);
                        target_user = ntohl(target_user);
                        if (!rooms.contains(target_room)) return;
                        rooms.at(target_room).users.erase(target_user);
                        user2room.erase(target_user); // FIX: was missing previously
                    } break;

                    case Commands::CREATE: {
                        // Expect: [CMD(1)] [name~password (variable)]
                        if (cmd.size() < 2) return;
                        std::string data(cmd.begin() + 1, cmd.end());
                        size_t sep = data.find('~');
                        if (sep == std::string::npos) return;
                        // FIX: was substr(0, sep-1) which dropped the last char of the name
                        std::string name = data.substr(0, sep);
                        std::string password = data.substr(sep + 1);
                        ID rid = generate_new_roomID();
                        rooms.emplace(rid, Room(name, password));
                        std::cout << "[ROOM] Created '" << name << "' (ID: " << rid << ")" << std::endl;
                        send_room_list(private_fd);
                    } break;

                    case Commands::DESTROY: {
                        // Expect: [CMD(1)] [room_id(4)]
                        if (cmd.size() < 1 + sizeof(ID)) return;
                        ID target_room;
                        memcpy(&target_room, cmd.data() + 1, sizeof(ID));
                        target_room = ntohl(target_room);
                        if (!rooms.contains(target_room)) return;

                        // FIX: build a proper vector<uint8_t> — reinterpret_cast<vector&>(string) is UB
                        std::string msg_str = "Room has been destroyed";
                        std::vector<uint8_t> msg_bytes(msg_str.begin(), msg_str.end());
                        // Send before erasing so the room member list is still valid
                        send_message_room(target_room, msg_bytes);
                        rooms.erase(target_room);
                        send_room_list(private_fd);
                    } break;

                    case Commands::DISCONNECT: {
                        // Expect: [CMD(1)] [user_id(4)]
                        if (cmd.size() < 1 + sizeof(ID)) return;
                        ID uid;
                        memcpy(&uid, cmd.data() + 1, sizeof(ID));
                        uid = ntohl(uid);
                        if (!users.contains(uid)) return;
                        end_connection(uid);
                    } break;
                }
            }

            // Fan-out a message buffer to every user in a room.
            // Spawns a detached thread per user; each thread owns its own copy of the data.
            void send_message_room(ID room_id, std::vector<uint8_t>& payload) {
                if (!rooms.contains(room_id)) return;
                Room& room = rooms.at(room_id);

                // Prepend 4-byte length in network byte order
                uint32_t net_len = htonl(static_cast<uint32_t>(payload.size()));
                std::vector<uint8_t> packet(4 + payload.size());
                memcpy(packet.data(), &net_len, 4);
                memcpy(packet.data() + 4, payload.data(), payload.size());

                for (auto uid : room.users) {
                    if (!users.contains(uid)) continue;
                    int ufd = users.at(uid);
                    // Each thread gets its own copy so lifetime is self-contained
                    std::thread([ufd, pkt = packet]() {
                        size_t sent = 0;
                        while (sent < pkt.size()) {
                            // MSG_NOSIGNAL prevents SIGPIPE on broken connections
                            ssize_t n = send(ufd, pkt.data() + sent, pkt.size() - sent, MSG_NOSIGNAL);
                            if (n <= 0) break; // Connection gone; abandon silently
                            sent += n;
                        }
                    }).detach();
                }
            }

            // FIX: renamed from send_message(SecureBuffer&) to avoid silent overload ambiguity
            void send_message(SecureBuffer<uint8_t>& msg) {
                if (msg.size() < 4) return;
                uint32_t dest;
                memcpy(&dest, msg.data(), sizeof(uint32_t));
                dest = ntohl(dest);

                // The first 4 bytes are the destination room ID, not payload length.
                // Build the actual payload as everything after the room ID.
                std::vector<uint8_t> payload(msg.begin() + 4, msg.end());
                send_message_room(dest, payload);
            }

            // Send a framed packet directly to a single fd (e.g. the Python bridge)
            void send_message_fd(int dest, std::vector<uint8_t>& data) {
                if (dest < 0) return;
                uint32_t net_len = htonl(static_cast<uint32_t>(data.size()));
                std::vector<uint8_t> packet(4 + data.size());
                memcpy(packet.data(), &net_len, 4);
                memcpy(packet.data() + 4, data.data(), data.size());

                std::thread([dest, pkt = std::move(packet)]() {
                    size_t sent = 0;
                    while (sent < pkt.size()) {
                        ssize_t n = send(dest, pkt.data() + sent, pkt.size() - sent, MSG_NOSIGNAL);
                        if (n <= 0) break;
                        sent += n;
                    }
                }).detach();
            }

            void parse_message(int fd) {
            SecureBuffer<uint8_t> buffer;
            try {
                read_message(fd, buffer);
            } catch (const std::exception& e) {
                std::cerr << "[READ ERROR] " << e.what() << std::endl;
                end_connectionFD(fd);
                return;
            }

            if (buffer.empty()) return;

            MessageType type = static_cast<MessageType>(buffer.front());
            
            if (type == MessageType::MSG) {
                send_message(buffer);
            } else if (type == MessageType::CMD) {
                if (buffer.size() < 2) return; // Need at least [Type][Opcode]
                
                // Create a buffer for the command only (stripping MessageType)
                SecureBuffer<uint8_t> cmd(buffer.size() - 1);
                memcpy(cmd.data(), buffer.data() + 1, buffer.size() - 1);
                execute_command(cmd);
            } else {
                std::cout << "[WARN] Unknown MessageType: " << (int)type << std::endl;
            }
        }

        public:
            LocServ(int port = 12578) {
                if (port == 6666) throw std::runtime_error("Invalid Public Port: 6666 is reserved for the private bridge");

                for (int i = 0; i < 2; ++i) {
                    socket_descriptor[i] = socket(AF_INET, SOCK_STREAM, 0);
                    if (socket_descriptor[i] < 0) throw std::runtime_error("Failed to create socket");

                    int opt = 1;
                    setsockopt(socket_descriptor[i], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

                    address[i].sin_family = AF_INET;
                    address[i].sin_addr.s_addr = htonl(i == 0 ? INADDR_ANY : INADDR_LOOPBACK);
                    address[i].sin_port = htons(i == 0 ? port : 6666);

                    if (bind(socket_descriptor[i], (sockaddr*)&address[i], sizeof(address[i])) < 0)
                        throw std::runtime_error("Failed to bind socket " + std::to_string(i));
                    listen(socket_descriptor[i], i == 0 ? BACKLOG : 5);
                }
            }

            void run_server() {
                epoll_event event{}, events[MAX_EVENTS];

                for (int i = 0; i < 2; ++i) {
                    event.events = EPOLLIN;
                    event.data.fd = socket_descriptor[i];
                    if (epoll_ctl(event_manager, EPOLL_CTL_ADD, socket_descriptor[i], &event) == -1)
                        throw std::runtime_error("Failed to add master socket to epoll");
                }

                while (true) {
                    int num_ready = epoll_wait(event_manager, events, MAX_EVENTS, -1);
                    if (num_ready < 0) {
                        if (errno == EINTR) continue; // Interrupted by signal — retry
                        throw std::runtime_error("epoll_wait failed");
                    }

                    for (int i = 0; i < num_ready; ++i) {
                        int current_fd = events[i].data.fd;

                        if (current_fd == socket_descriptor[0]) {
                            accept_new_connection<false>();
                        } else if (current_fd == socket_descriptor[1]) {
                            accept_new_connection<true>();
                        } else {
                            try {
                                parse_message(current_fd);
                            } catch (const std::exception& e) {
                                std::cerr << "[ERROR] FD " << current_fd << ": " << e.what() << std::endl;
                                if (current_fd == private_fd) {
                                    private_fd = -1;
                                    std::cout << "[CONTROL] Python bridge disconnected." << std::endl;
                                }
                                // end_connectionFD handles EPOLL_CTL_DEL + close
                                end_connectionFD(current_fd);
                            }
                        }
                    }
                }
            }
    };
}

#endif