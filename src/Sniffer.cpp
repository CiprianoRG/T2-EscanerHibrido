/**
 * MÓDULO DE CAPTURA DE PAQUETES (SNIFFER)
 * 
 * Responsabilidad: Capturar las primeras tramas de respuesta de puertos abiertos
 * 
 * Funcionalidades principales:
 * - sniffer(): Función principal de captura con timeout
 * - procesar_paquete(): Callback para análisis de cada paquete capturado
 * - Filtrado BPF dinámico basado en puertos abiertos
 * 
 * Características técnicas:
 * - Usa libpcap con select() para comportamiento no-bloqueante
 * - Filtro BPF: "(tcp or udp) and (src port X or src port Y...)"
 * - Captura primeros N bytes de cabeceras de transporte
 * - Detección automática de protocolo (TCP/UDP) y puerto origen
 * - Timeout configurable con salida garantizada
 * 
 * Flujo de captura:
 * 1. Configurar interfaz en modo promiscuo
 * 2. Compilar y aplicar filtro BPF dinámico
 * 3. Capturar paquetes con pcap_dispatch + select()
 * 4. Procesar cada paquete con callback
 * 5. Extraer puerto, protocolo y primeros bytes
 * 6. Terminar por timeout o captura completa
 * 
 * Dependencias: libpcap, netinet/ip.h, netinet/tcp.h, netinet/udp.h
 */

#include "Sniffer.h"   
#include <pcap.h>
#include <cstring>
#include <iostream>
#include <unordered_set>
#include <map>
#include <vector>
#include <chrono>
#include <thread>
#include <algorithm>
#include <sstream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <sys/select.h>

using namespace std;

// Definir EstadoSniffer ANTES de cualquier función que lo use
struct EstadoSniffer {
    vector<int> puertos_vistos;
    int bytes_a_guardar;
    map<int, vector<uint8_t>> primeros_bytes;
    unordered_set<int> puertos_guardados;
};


// Callback para pcap_dispatch
void procesar_paquete(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    auto* estado = (EstadoSniffer*)user;
    
    // Parseo básico del paquete
    if (header->caplen < sizeof(struct ether_header)) return;
    const struct ether_header *eth = (const struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const struct ip *ip_hdr = (const struct ip*)(packet + sizeof(struct ether_header));
    size_t ip_len = ip_hdr->ip_hl * 4;
    const u_char *ptr_transporte = (const u_char*)ip_hdr + ip_len;

    uint16_t puerto = 0;
    string protocolo;

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr*)ptr_transporte;
        puerto = ntohs(tcp->th_sport);
        protocolo = "TCP";
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp = (const struct udphdr*)ptr_transporte;
        puerto = ntohs(udp->uh_sport);
        protocolo = "UDP";
    } else return;

    // Verificar si es un puerto de interés
    bool puerto_interesante = false;
    for (int p : estado->puertos_vistos) {
        if (p == puerto) {
            puerto_interesante = true;
            break;
        }
    }
    if (!puerto_interesante) return;

    // Verificar si ya capturamos este puerto
    if (estado->puertos_guardados.find(puerto) != estado->puertos_guardados.end()) {
        return;
    }

    // Capturar bytes
    size_t offset_transporte = ptr_transporte - packet;
    size_t disponibles = (header->caplen > offset_transporte) ? (header->caplen - offset_transporte) : 0;
    int bytes_a_tomar = min((size_t)estado->bytes_a_guardar, disponibles);
    
    vector<uint8_t> bytes_guardados;
    for (int i = 0; i < bytes_a_tomar; ++i) {
        bytes_guardados.push_back(ptr_transporte[i]);
    }

    // Guardar datos
    estado->primeros_bytes[puerto] = bytes_guardados;
    estado->puertos_guardados.insert(puerto);
    
    cout << "Sniffer: Capturado puerto " << puerto << "/" << protocolo 
         << " - " << bytes_guardados.size() << " bytes" << endl;
}

// IMPLEMENTACIÓN CON SELECT() - GARANTIZADO NO BLOQUEANTE

int sniffer(const string &interfaz_red, const string &ip_objetivo, const vector<int> &puertos_abiertos,
            int bytes_a_capturar, int timeout_ms, vector<DatosCapturados> &datos_capturados, string &mensaje_error) {
    (void)ip_objetivo; // Silenciar advertencia de parámetro no usado
    datos_capturados.clear();
    mensaje_error.clear();

    if (puertos_abiertos.empty()) {
        return 0; // No hay puertos para capturar
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interfaz_red.c_str(), 65535, 1, 100, errbuf);
    if (!handle) {
        mensaje_error = string("pcap_open_live falló: ") + errbuf;
        return -1;
    }

    // Configurar filtro BPF
    //string filtro = "src host " + ip_objetivo + " and (tcp or udp) and (";
    // Configurar filtro BPF
    string filtro = "(tcp or udp) and (";
    for (size_t i = 0; i < puertos_abiertos.size(); ++i) {
    	if (i) filtro += " or ";
    	filtro += "src port " + to_string(puertos_abiertos[i]);
	}	
	filtro += ")";

	cout << "Sniffer: Filtro aplicado: " << filtro << endl;  // Para debug

	struct bpf_program fp;
	if (pcap_compile(handle, &fp, filtro.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
    		mensaje_error = string("pcap_compile falló: ") + pcap_geterr(handle);
    		pcap_close(handle);
    		return -2;
		}	
// ... resto del código
    if (pcap_setfilter(handle, &fp) == -1) {
        mensaje_error = string("pcap_setfilter falló: ") + pcap_geterr(handle);
        pcap_freecode(&fp);
        pcap_close(handle);
        return -3;
    }
    pcap_freecode(&fp);

    cout << "Sniffer: Filtro aplicado: " << filtro << endl;
    cout << "Sniffer: Timeout: " << timeout_ms << "ms" << endl;

    // Obtener file descriptor para select()
    int pcap_fd = pcap_get_selectable_fd(handle);
    if (pcap_fd == -1) {
        mensaje_error = "No se puede obtener fd para select()";
        pcap_close(handle);
        return -4;
    }

    EstadoSniffer estado;
    estado.bytes_a_guardar = bytes_a_capturar;
    estado.puertos_vistos = puertos_abiertos;

    auto inicio = chrono::steady_clock::now();
    int paquetes_procesados = 0;

    // LOOP PRINCIPAL CON SELECT() - 100% NO BLOQUEANTE
    while (true) {
        // Verificar timeout global
        auto ahora = chrono::steady_clock::now();
        auto tiempo_transcurrido = chrono::duration_cast<chrono::milliseconds>(ahora - inicio).count();
        if (tiempo_transcurrido >= timeout_ms) {
            cout << "Sniffer: Timeout alcanzado (" << tiempo_transcurrido << "ms)" << endl;
            break;
        }

        // Usar select() para esperar paquetes con timeout
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(pcap_fd, &readfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms timeout para select

        int ret = select(pcap_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (ret == -1) {
            // Error en select
            mensaje_error = "Error en select()";
            break;
        } 
        else if (ret == 0) {
            // Timeout de select - no hay paquetes, continuar
            continue;
        } 
        else if (FD_ISSET(pcap_fd, &readfds)) {
            // Hay paquetes disponibles - procesar con pcap_dispatch
            ret = pcap_dispatch(handle, 10, procesar_paquete, (u_char*)&estado);
            if (ret > 0) {
                paquetes_procesados += ret;
            }
            else if (ret == -1) {
                mensaje_error = string("Error en pcap_dispatch: ") + pcap_geterr(handle);
                break;
            }
        }

        // Verificar si ya capturamos todos los puertos
        if (estado.puertos_guardados.size() >= puertos_abiertos.size()) {
            cout << "Sniffer: Todos los puertos capturados (" 
                 << estado.puertos_guardados.size() << "/" << puertos_abiertos.size() << ")" << endl;
            break;
        }

        // Pequeña pausa opcional
        this_thread::sleep_for(chrono::milliseconds(1));
    }

    // Preparar datos de retorno
    for (const auto &par : estado.primeros_bytes) {
        DatosCapturados datos;
        datos.puerto = par.first;
        datos.primeros_bytes = par.second;
        datos.protocolo = "TCP/UDP";
        datos_capturados.push_back(datos);
    }

    pcap_close(handle);
    
    cout << "Sniffer finalizado: " << datos_capturados.size() << " puertos capturados, " 
         << paquetes_procesados << " paquetes procesados" << endl;
    
    return 0;
}
