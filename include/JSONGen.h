// JSONGen.h
#ifndef JSONGEN_H
#define JSONGEN_H

#include <string>
#include <vector>
#include <cstdint>  // para uint8_t

// Se espera que esta sea la estructura de datos para los resultados del escaneo y sniffing.
struct ScanResult {
    std::string ip;
    int port;
    std::string protocol; // "TCP" or "UDP"
    std::string service;  // Puede estar vacío si no se detecta ningún servicio
    std::vector<uint8_t> header; // primeros N bytes de la respuesta (puede estar vacío)
};

/// Genera un JSON bonito en 'filename' con los resultados.
/// Devuelve true en caso de éxito, false en caso de error (mensaje en error_out).
bool generarJSON(const std::string &filename,
                 const std::vector<ScanResult>& resultados,
                 std::string &error_out);

#endif // JSONGEN_H
