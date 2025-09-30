/**
 * MÓDULO DE ESCANEO DE PUERTOS
 * 
 * Responsabilidad: Realizar escaneo activo de puertos TCP y UDP
 * 
 * Funcionalidades principales:
 * - escanear_concurrente(): Coordina escaneo simultáneo TCP/UDP
 * - escanear_puerto_tcp(): Escaneo individual TCP con detección de estados
 * - escanear_puerto_udp(): Escaneo individual UDP con envío de datagramas
 * - servicio_estimado(): Mapeo de puertos a servicios conocidos
 * 
 * Estados detectados:
 * - TCP: "Abierto", "Cerrado", "Filtrado", "Error"
 * - UDP: "Abierto", "Cerrado/Filtrado", "Error"
 * 
 * Técnicas utilizadas:
 * - Conexiones TCP no bloqueantes con select()
 * - Envío de datagramas UDP vacíos
 * - Concurrencia con std::async y std::future
 * - Timeouts configurables por socket
 * 
 * Dependencias: sys/socket.h, netinet/in.h, arpa/inet.h, unistd.h
 */


#include "Escaner.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <fcntl.h>
#include <errno.h>
#include <thread>
#include <vector>
#include <future>
// Los cambios realizados fueron hechos para adaptarlo a los requerimentos de la tarea, se implementa correctamente la concurrencia con el uso de hilos, ahora el escaneo TCP y UDP responden a diferentes funciones, con esto se espera que los tiempos de espera reduzcan a la mitad. Lo proximo sera implementar concurrencia entre el escaneo de puertos y el sniffer
using namespace std;

// ================== ESCANEO TCP CONCURRENTE ==================

ResultadoEscaneo escanear_puerto_tcp(const string& ip, int puerto, int timeout_ms) {
    ResultadoEscaneo resultado;
    resultado.puerto = puerto;
    resultado.protocolo = "TCP";
    resultado.servicio = servicio_estimado(puerto);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        resultado.estado = "Error";
        return resultado;
    }

    // Configurar timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dir;
    dir.sin_family = AF_INET;
    dir.sin_port = htons(puerto);
    dir.sin_addr.s_addr = inet_addr(ip.c_str());

    int conexion = connect(sock, (struct sockaddr*)&dir, sizeof(dir));
    close(sock);


    if (conexion == 0) {
    /*
    // ESTOS DOS BLOQUES SON PARA FORZAR EL TRAFICO Y PODER DETECTARLO EN EL SNIFFER, SOLO PARA PRUEBAS
        // Enviar datos para generar tráfico capturable
        const char *payload = "GET / HTTP/1.0\r\n\r\n";
        send(sock, payload, strlen(payload), 0);
    
    // Intentar recibir respuesta breve
    	char buffer[128];
    	recv(sock, buffer, sizeof(buffer), MSG_DONTWAIT);
    */
        resultado.estado = "Abierto";
    } else {
        // Intentar con timeout más corto para detectar filtrado
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            tv.tv_sec = 0;
            tv.tv_usec = 100000; // 100ms
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            
            conexion = connect(sock, (struct sockaddr*)&dir, sizeof(dir));
            close(sock);
            
            if (conexion == 0) {
                resultado.estado = "Filtrado";
            } else {
                resultado.estado = "Cerrado";
            }
        } else {
            resultado.estado = "Cerrado";
        }
    }
    
    return resultado;
}

vector<ResultadoEscaneo> escanear_tcp_concurrente(const string& ip, 
                                                 const vector<int>& puertos, 
                                                 int timeout_ms) {
    vector<ResultadoEscaneo> resultados;
    vector<future<ResultadoEscaneo>> futures;

    cout << "Iniciando escaneo TCP concurrente de " << puertos.size() << " puertos..." << endl;

    // Lanzar todos los escaneos TCP en paralelo
    for (int puerto : puertos) {
        futures.push_back(async(launch::async, escanear_puerto_tcp, ip, puerto, timeout_ms));
    }

    // Recoger resultados
    for (auto& future : futures) {
        resultados.push_back(future.get());
    }

    return resultados;
}

// ================== ESCANEO UDP CONCURRENTE ==================

ResultadoEscaneo escanear_puerto_udp(const string& ip, int puerto, int timeout_ms) {
    ResultadoEscaneo resultado;
    resultado.puerto = puerto;
    resultado.protocolo = "UDP";
    resultado.servicio = servicio_estimado(puerto);
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        resultado.estado = "Error";
        return resultado;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dir;
    memset(&dir, 0, sizeof(dir));
    dir.sin_family = AF_INET;
    dir.sin_port = htons(puerto);
    dir.sin_addr.s_addr = inet_addr(ip.c_str());

    // Enviar datagrama de prueba
    const char *prueba = "UDP_SCAN";
    sendto(sock, prueba, strlen(prueba), 0, (struct sockaddr*)&dir, sizeof(dir));

    // Intentar recibir respuesta
    char buffer[1024];
    struct sockaddr_in dir_respuesta;
    socklen_t tamano = sizeof(dir_respuesta);
    int recibido = recvfrom(sock, buffer, sizeof(buffer), 0, 
                           (struct sockaddr*)&dir_respuesta, &tamano);
    
    close(sock);

    if (recibido > 0) {
        resultado.estado = "Abierto";
    } else {
        resultado.estado = "Cerrado/Filtrado";
    }
    
    return resultado;
}

vector<ResultadoEscaneo> escanear_udp_concurrente(const string& ip, 
                                                 const vector<int>& puertos, 
                                                 int timeout_ms) {
    vector<ResultadoEscaneo> resultados;
    vector<future<ResultadoEscaneo>> futures;

    cout << "Iniciando escaneo UDP concurrente de " << puertos.size() << " puertos..." << endl;

    // Lanzar todos los escaneos UDP en paralelo
    for (int puerto : puertos) {
        futures.push_back(async(launch::async, escanear_puerto_udp, ip, puerto, timeout_ms));
    }

    // Recoger resultados
    for (auto& future : futures) {
        resultados.push_back(future.get());
    }

    return resultados;
}

// ================== FUNCIÓN CONCURRENTE PRINCIPAL ==================

vector<ResultadoEscaneo> escanear_concurrente(const string& ip, 
                                             const vector<int>& puertos, 
                                             int timeout_ms) {
    cout << "Iniciando escaneo CONCURRENTE TCP/UDP..." << endl;

    // EJECUTAR TCP y UDP AL MISMO TIEMPO; ahora si hay cocurrencia
    auto future_tcp = async(launch::async, escanear_tcp_concurrente, ip, puertos, timeout_ms);
    auto future_udp = async(launch::async, escanear_udp_concurrente, ip, puertos, timeout_ms);

    // Esperar que ambos terminen
    auto resultados_tcp = future_tcp.get();
    auto resultados_udp = future_udp.get();

    // Combinar resultados
    vector<ResultadoEscaneo> todos_resultados;
    todos_resultados.insert(todos_resultados.end(), resultados_tcp.begin(), resultados_tcp.end());
    todos_resultados.insert(todos_resultados.end(), resultados_udp.begin(), resultados_udp.end());

    cout << "Escaneo concurrente completado: " 
         << resultados_tcp.size() << " TCP + " 
         << resultados_udp.size() << " UDP = " 
         << todos_resultados.size() << " resultados totales" << endl;

    return todos_resultados;
}

// ================== FUNCIONES LEGACY (para compatibilidad) ==================

vector<ResultadoEscaneo> escanear_rango(const string& ip, const vector<int>& puertos, 
                                       int timeout_ms, const string& tipo) {
    if (tipo == "TCP") {
        return escanear_tcp_concurrente(ip, puertos, timeout_ms);
    } else if (tipo == "UDP") {
        return escanear_udp_concurrente(ip, puertos, timeout_ms);
    }
    return vector<ResultadoEscaneo>();
}

// ================== FUNCIONES EXISTENTES ==================

string servicio_estimado(int puerto) {
    switch(puerto) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 143: return "imap";
        case 443: return "https";
        case 3306: return "mysql";
        case 3389: return "rdp";
        default: return "desconocido";
    }
}
