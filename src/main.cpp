#include "LocServ.hpp"

int main() {
    try {
        conclave::LocServ server(1300);
        server.run_server();
    } catch (...) {
        return 1;
    }
    return 0;
}