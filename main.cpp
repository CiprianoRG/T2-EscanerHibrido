/**
 * PROGRAMA PRINCIPAL - ESCÁNER HÍBRIDO DE PUERTOS CON SNIFFING
 * 
 * Propósito:
 * - Escanear puertos TCP y UDP de un objetivo específico
 * - Capturar las primeras tramas de respuesta de puertos abiertos
 * - Generar reporte JSON con servicios detectados y cabeceras de paquetes
 * 
 * Flujo del programa:
 * 1. ENTRADA: Solicita IP, rango de puertos, timeout y archivo de salida
 * 2. VALIDACIÓN: Verifica formatos y rangos usando Validaciones.h
 * 3. ESCANEO: Ejecuta escaneo concurrente TCP/UDP usando Escaner.h
 * 4. SNIFFING: Captura tráfico de respuesta de puertos abiertos usando Sniffer.h  
 * 5. REPORTE: Genera archivo JSON estructurado usando JSONGen.h
 * 
 * Características:
 * - Concurrencia entre escaneo TCP y UDP
 * - Detección automática de interfaz de red
 * - Timeouts configurables por usuario
 * - Filtrado inteligente de paquetes
 * - Output en consola y archivo JSON
 * 
 * Uso: ./escaner_hibrido
 * Requiere: permisos root para sniffing (sudo)
 */
 
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <algorithm>

// Nuestros módulos
#include "Validaciones.h"
#include "Escaner.h"
#include "Sniffer.h"
#include "JSONGen.h"

using namespace std;

// ================== FUNCIONES DE ENTRADA (del main orignal) ==================

static vector<int> range_ports(const string &s) {//convierte un string a una lista de puertos
    size_t dash = s.find('-');  // Busca si hay un guion
    vector<int> v;  // Aquí guardaremos los puertos
    
    if (dash == string::npos) {//si no tiene guien en medio de los numero lo toma solito
        try { 
            v.push_back(stoi(s));  // Convierte el string a numero y lo agrega
        } catch(...) {}  // Si falla la conversion no hace nada
        return v;  // Regresamos el vector con un solo puerto 
    }
    
    try { //si hay un guin entre los numero entonces lo toma como rango
        int a = stoi(s.substr(0,dash));  // Extrae el primer numero
        int b = stoi(s.substr(dash+1));  // Extrae el segundo numero
        if (a > b) swap(a,b);  // Si el primero es mayor, los intercambia
        for (int p = a; p <= b; ++p) v.push_back(p);  // Crea todos los numeros del rango
    } catch(...) {}  // Si algo sale mal no hace nada
    return v;  // Regresa la lista de puertos
}

// ================== FUNCIÓN PARA OBTENER INTERFAZ AUTOMÁTICA ==================

string obtener_interfaz_por_defecto(const string& ip_objetivo) {
    // Si la IP es localhost, usar 'lo' directamente
    if (ip_objetivo == "127.0.0.1" || ip_objetivo == "localhost") {
        return "lo";
    }
    
    // Para otras IPs, detectar automáticamente
    pcap_if_t *interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        return "eth0"; // Fallback por defecto
    }
    
    string interfaz = "eth0"; // Valor por defecto
    for (pcap_if_t *dev = interfaces; dev != nullptr; dev = dev->next) {
        // Preferir interfaces que no sean loopback y estén activas
        if (!(dev->flags & PCAP_IF_LOOPBACK) && (dev->flags & PCAP_IF_UP)) {
            interfaz = dev->name;
            break;
        }
    }
    
    pcap_freealldevs(interfaces);
    return interfaz;
}

// ================== FUNCIÓN PARA CONVERTIR RESULTADOS ==================

vector<ScanResult> convertir_a_scanresult(const vector<ResultadoEscaneo>& escaneos, 
                                         const vector<DatosCapturados>& capturas,
                                         const string& ip) {
    vector<ScanResult> resultados;
    
    for (const auto& escaneo : escaneos) {
        // Solo incluir puertos abiertos en el JSON
        if (escaneo.estado.find("Abierto") == string::npos) continue;
        
        ScanResult sr;
        sr.ip = ip;
        sr.port = escaneo.puerto;
        sr.protocol = escaneo.protocolo;
        sr.service = escaneo.servicio;
        
        // Buscar bytes capturados para este puerto
        for (const auto& captura : capturas) {
            if (captura.puerto == escaneo.puerto) {
                sr.header = captura.primeros_bytes;
                break;
            }
        }
        
        resultados.push_back(sr);
    }
    
    return resultados;
}

// ================== FUNCIÓN PRINCIPAL ==================

int main() {
    cout << "=== Escáner Híbrido de Puertos y Sniffing ===\n\n";
    
    // Variables de entrada (formato de tu compañera)
    string ip, port_range, out = "resultado.json";
    int timeout = 1000;

    // ================== ENTRADA DE DATOS (de tu compañera) ==================
    cout << "IP objetivo: "; //valida la ip 
    getline(cin, ip);  // Lee toda la línea (por si hay espacios)
    if(!IP_valida(ip)) {  // Usa tu función para ver si la IP es válida
        cerr << "IP inválida\n";  // Muestra error en rojo (cerr)
        return 1;  // Termina el programa con código de error
    }

    cout << "Rango puertos (ej. 20-80): "; //pide los puertos
    getline(cin, port_range);
    auto puertos = range_ports(port_range);  // Convierte el string a lista de números
    if(puertos.empty()) {  // Si no se pudo convertir ningun puerto
        cerr << "Puertos inválidos\n"; 
        return 1; 
    }
   
    for(int p : puertos) { // Verifica que cada puerto individual sea valido
        if(!Puerto_valido(p)) {
            cerr << "Puerto inválido: " << p << "\n";
            return 1;
        }
    }

    cout << "Timeout ms [1000]: "; //pedimos el tiempo de espera en milisegundos 
    string t; 
    getline(cin, t); 
    if(!t.empty()) timeout = stoi(t);  // Si el usuario escribio algo usa ese valor
    if(!Timeout_valido(timeout)) {  // Valida que el timeout sea razonable
        cerr << "Timeout inválido\n"; 
        return 1; 
    }

    cout << "Archivo salida JSON [resultado.json]: "; //aqui da el json de salida
    string o; 
    getline(cin, o); 
    if(!o.empty()) out = o;  // Si el usuario escribió algo usa ese nombre

    // ================== CONFIGURACIÓN AUTOMÁTICA ==================
    
    // Obtener interfaz de red automáticamente
    string interfaz_red = obtener_interfaz_por_defecto(ip);
    cout << "\nUsando interfaz: " << interfaz_red << endl;
    
    // Validar interfaz
    if (!Interfaz_valida(interfaz_red)) {
        cerr << "Error: Interfaz de red no válida.\n";
        return 1;
    }
/*
    // Optimización: límite de puertos para prueba
    if (puertos.size() > 50) {
        cout << "Optimización: Escaneando solo primeros 50 puertos...\n";
        puertos.resize(50);
    }
*/
    cout << "Iniciando escaneo de " << puertos.size() << " puertos...\n";
    cout << "Objetivo: " << ip << "\n";
    cout << "Timeout: " << timeout << "ms\n\n";

    // Vectores para resultados
    vector<ResultadoEscaneo> resultados_escaneo;
    vector<DatosCapturados> datos_capturados;

    // ================== FASE 1: ESCANEO CONCURRENTE ==================
    cout << "=== FASE 1: Escaneo de Puertos ===\n";
    
    auto inicio_escaneo = chrono::steady_clock::now();
    
    // USAR ESCANEO CONCURRENTE MEJORADO
    resultados_escaneo = escanear_concurrente(ip, puertos, timeout);
    
    auto fin_escaneo = chrono::steady_clock::now();
    auto duracion_escaneo = chrono::duration_cast<chrono::milliseconds>(fin_escaneo - inicio_escaneo);

    
    // ================== MOSTRAR RESULTADOS (SOLO ABIERTOS - FORMATO COMPACTO) ==================
    set<int> abiertos;  // Usamos set para evitar duplicados automáticamente
    
    // Recolectar y mostrar puertos abiertos
    cout << "\n--- Puertos Abiertos ---\n";
    
    for(const auto& r : resultados_escaneo) {
        if(r.estado == "Abierto") {
            abiertos.insert(r.puerto);
            cout << r.protocolo << " " << r.puerto << " - " << r.servicio << "\n"; 
        }
    }
    
    if (abiertos.empty()) {
        cout << "No se encontraron puertos abiertos.\n";
    } else {
        cout << "\nTotal: " << abiertos.size() << " puertos abiertos\n";
    }

    // ================== FASE 2: SNIFFING  ==================
    if(!abiertos.empty()) {
        cout << "\n=== FASE 2: Captura de Paquetes ===\n";
        
        vector<int> puertos_abiertos(abiertos.begin(), abiertos.end());
        cout << "Capturando tráfico de " << puertos_abiertos.size() << " puertos abiertos...\n";
        
        string mensaje_error;
        
        // OPTIMIZACIÓN: Timeout más corto para sniffer
        int sniff_timeout = min(2000, timeout);
        
        auto inicio_sniffing = chrono::steady_clock::now();
        int resultado_sniffer = sniffer(interfaz_red, ip, puertos_abiertos, 16, sniff_timeout, datos_capturados, mensaje_error);
        auto fin_sniffing = chrono::steady_clock::now();
        auto duracion_sniffing = chrono::duration_cast<chrono::milliseconds>(fin_sniffing - inicio_sniffing);
        
        if(resultado_sniffer == 0) {
            cout << "Captura completada en " << duracion_sniffing.count() << "ms. ";
            cout << "Datos capturados de " << datos_capturados.size() << " puertos.\n";
        } else {
            cout << "Sniffer: " << mensaje_error << "\n";
        }
    } else {
        cout << "\nNo hay puertos abiertos para capturar.\n";
    }

    // ================== FASE 3: GENERACIÓN JSON MEJORADA ==================
    cout << "\n=== FASE 3: Generación de Reporte JSON ===\n";
    
    if (!abiertos.empty()) {
        auto scan_results = convertir_a_scanresult(resultados_escaneo, datos_capturados, ip);
        
        string error_json;
        if (generarJSON(out, scan_results, error_json)) {
            cout << "Reporte JSON generado exitosamente: " << out << "\n";
        } else {
            cout << "Error generando JSON: " << error_json << "\n";
        }
    } else {
        cout << "No hay puertos abiertos para generar reporte JSON.\n";
        
        // Crear JSON vacío para cumplir con el formato
        vector<ScanResult> vacio;
        string error_json;
        generarJSON(out, vacio, error_json);
    }

    // ================== ESTADÍSTICAS FINALES ==================
    cout << "\n=== ESCANEO COMPLETADO ===\n";
    cout << "Estadísticas:\n";
    cout << "  • Puertos escaneados: " << puertos.size() * 2 << " (TCP + UDP)\n";
    cout << "  • Puertos abiertos: " << abiertos.size() << "\n";
    cout << "  • Datos capturados: " << datos_capturados.size() << "\n";
    cout << "  • Tiempo de escaneo: " << duracion_escaneo.count() << "ms\n";
    cout << "  • Archivo generado: " << out << "\n";

    return 0;  
}
