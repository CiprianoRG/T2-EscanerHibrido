#ifndef VALIDACIONES_H
#define VALIDACIONES_H

#include <string>
#include <pcap.h>
#include <vector>


bool IP_valida(const std::string &IP);
bool Puerto_valido(int puerto);
bool Rango_puertos_valido(int puerto_inicio, int puerto_fin);  // Esta es nueva
bool Lista_puertos_valida(const std::vector<int>& puertos);    // Y esta tambien
bool Timeout_valido(int timeout_ms);
bool Interfaz_valida(const std::string &nombre);
bool Snapvalido(int snaplen);
bool Filtrovalido(const std::string &filtro, pcap_t *handle);

#endif
