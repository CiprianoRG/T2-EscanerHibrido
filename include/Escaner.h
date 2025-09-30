#ifndef ESCANER_H
#define ESCANER_H

#include <string>
#include <vector>
#include <cstdint>
#include <future>

struct ResultadoEscaneo {
    int puerto;
    std::string protocolo;
    std::string estado;
    std::string servicio;
    std::vector<uint8_t> header_bytes;
};

// Función concurrente TCP y UDP, con esto vamos a implementar correctamente la concurrencia en el escaneo de puertos
std::vector<ResultadoEscaneo> escanear_concurrente(
    const std::string& ip, 
    const std::vector<int>& puertos, 
    int timeout_ms);

// NUEVA: Funciones individuales para hilos
std::vector<ResultadoEscaneo> escanear_tcp_concurrente(
    const std::string& ip, 
    const std::vector<int>& puertos, 
    int timeout_ms);

std::vector<ResultadoEscaneo> escanear_udp_concurrente(
    const std::string& ip, 
    const std::vector<int>& puertos, 
    int timeout_ms);

// Función legacy se queda para mantener la compatibilidad con veriones anteriores
std::vector<ResultadoEscaneo> escanear_rango(const std::string& IP, 
    const std::vector<int>& puertos, int timeout_ms, const std::string& tipo);

// Es para identificar el servicio por en numero de puerto
std::string servicio_estimado(int puerto);

#endif
