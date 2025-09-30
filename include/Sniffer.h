#ifndef SNIFFER_H
#define SNIFFER_H
#include <pcap.h>
#include <string>
#include <vector>
#include <map>
#include <cstdint> 

struct DatosCapturados {
    int puerto;
    std::string protocolo; // TCP o UDP
    std::vector<uint8_t> primeros_bytes; // Se cambio esto a uint8_t para tener consistencia
};

int sniffer(const std::string &interfaz_red, const std::string &ip_objetivo, const std::vector<int> &puertos_abiertos,
                int bytes_a_capturar, int timeout_ms, std::vector<DatosCapturados> &datos_capturados, std::string &mensaje_error);
                

#endif
