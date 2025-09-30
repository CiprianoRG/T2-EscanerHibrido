/**
 * MÓDULO DE GENERACIÓN DE REPORTES JSON
 * 
 * Responsabilidad: Convertir resultados de escaneo a formato JSON estructurado
 * 
 * Funcionalidades principales:
 * - generarJSON(): Crea archivo JSON con pretty-printing
 * - bytesToHexString(): Convierte bytes a string hexadecimal formateado
 * 
 * Estructura JSON generada:
 * [
 *   {
 *     "ip": "192.168.1.100",
 *     "port": 22,
 *     "protocol": "TCP",
 *     "service": "ssh",
 *     "header_bytes": "45 00 00 34 12 34 40 00"
 *   },
 *   ...
 * ]
 * 
 * Características:
 * - Formato consistente con especificaciones del proyecto
 * - Manejo de errores con excepciones
 * - Thread-safe con std::mutex
 * - Pretty-printing con indentación
 * - Campos opcionales manejados como null
 * 
 * Dependencias: nlohmann/json (header-only), fstream, iomanip
 */


#include "JSONGen.h"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <mutex>
#include <cstdint>

// nlohmann/json header-only
// https://github.com/nlohmann/json
#include <nlohmann/json.hpp>
using json = nlohmann::json;

static std::mutex g_json_mutex; // para proteger escritura si hay concurrencia

// Helper: convierte vector<uint8_t> a string hex "45 00 00 ..."
static std::string bytesToHexString(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return "";
    std::ostringstream oss;
    oss << std::uppercase << std::hex;
    bool first = true;
    for (uint8_t b : bytes) {
        if (!first) oss << ' ';
        oss << std::setw(2) << std::setfill('0') << (int)b;
        first = false;
    }
    // devolver en mayúscula con espacios
    return oss.str();
}

bool generarJSON(const std::string &filename,
                 const std::vector<ScanResult>& resultados,
                 std::string &error_out) {
    try {
        // Construir JSON: un array de objetos
        json a = json::array();

        for (const auto& r : resultados) {
            json obj;
            obj["ip"] = r.ip;
            obj["port"] = r.port;
            obj["protocol"] = r.protocol;
            obj["service"] = r.service.empty() ? nullptr : json(r.service);
            obj["header_bytes"] = bytesToHexString(r.header);
            a.push_back(obj);
        }

        // Para evitar contención en concurrencia, proteger la escritura
        std::lock_guard<std::mutex> lock(g_json_mutex);

        std::ofstream out(filename);
        if (!out.is_open()) {
            error_out = "No se pudo abrir el archivo para escritura: " + filename;
            return false;
        }
        out << std::setw(4) << a << std::endl; // pretty print
        out.close();
        return true;
    } catch (const std::exception& ex) {
        error_out = std::string("Excepcion en generarJSON: ") + ex.what();
        return false;
    } catch (...) {
        error_out = "Error desconocido en generarJSON";
        return false;
    }
}
