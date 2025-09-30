/**
 * MÓDULO DE VALIDACIÓN DE ENTRADAS
 * 
 * Responsabilidad: Validar formatos y rangos de datos de entrada
 * 
 * Funciones de validación:
 * - IP_valida(): Formato IPv4 con octetos 0-255, sin leading zeros
 * - Puerto_valido(): Rango 1-65535
 * - Rango_puertos_valido(): Inicio <= Fin, ambos válidos
 * - Timeout_valido(): 1-30000 ms (0.001-30 segundos)
 * - Interfaz_valida(): Verifica existencia con pcap_findalldevs()
 * - Snapvalido(): 1-65535 bytes para captura
 * - Filtrovalido(): Sintaxis BPF correcta con pcap_compile()
 * 
 * Criterios de validación:
 * - IP: 4 octetos, formato decimal, rangos válidos
 * - Puertos: enteros positivos dentro de rango estándar
 * - Timeout: suficiente para escaneo pero no excesivo
 * - Interfaz: existe y está disponible en el sistema
 * 
 * Dependencias: pcap.h para validación de interfaces y filtros
 */


#include "Validaciones.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>//crea arreglos que pueden cambiar de tamano
#include <cctype>//ayuda a validar que tipo de dato es
#include <pcap.h>
using namespace std;

//Validacion de ip

bool IP_valida(const string & IP){ //bool es para verificar que los valores dentro de la variable son verdaderos (o sea que si e valida la ip)
    stringstream ss(IP); // permite variar entre entrada y salida de datos string
    string segmento; //cada octeto de la IP
    vector<string> partes; //se crea un arreglo con las partes de la IP (on sea deebe de tener 4 partes o segmentos cada IP)

    while (getline(ss, segmento, '.')){ //getline ayuda a tomar lo datos de la IP completa, ss nos ayudara a asignar los octetos a la variable segmentos y el '.' nos ayuda a separar junto con ss los actetos de la IP
        partes.push_back(segmento); // push_back ayuda a anadir una parte al segmento de la IP
    }

    //validar las partes de  la ip
    if (partes.size()!=4){ //el tamano de las partes es diferente de 4
        return false;
    }

    for (const string & parte : partes ){ //vamos de parte en parte de la IP
        if (parte.empty()) return false; // si alguna esta vacia regresa un falso

        for (char c : parte){// recorre cada caracter de la parte (octeto) de la IP
            if (!isdigit(static_cast<unsigned char>(c))) return false; //valida si el caracter es un numero
        }

        int convertir_num = stoi(parte); //covierte los valores de parte a int

        if (convertir_num <0 || convertir_num > 255 ) return false; //validamos que el segmento de la ip (octeto) se encuentre en el rango de 0-255
        if (parte.size() > 1 && parte[0] == '0') return false; // valida que el tamano de cada parte debe ser solo de uno, o sea deben existir 4 partes (octetos), pero cada parte u octeto individual  solo debe estar el solito
    }

    return true; // si no ocurrio alguna de las excpeciones anteriores entonces la IP es valida
}


//Validacion para los puertos

bool Puerto_valido(int puerto){
    // recibe un solo puerto en int, validamos rango y tipo (ya int)
    if (puerto < 1 || puerto > 65535){
        cerr << "Error, el puerto debe estar entre 1 y 65535. \n";
        return false;
    }
    return true;
}

// esto es nomas para vaalidar el rango, necesario para el main
bool Rango_puertos_valido(int puerto_inicio, int puerto_fin) {
    if (!Puerto_valido(puerto_inicio) || !Puerto_valido(puerto_fin)) {
        return false;
    }
    return puerto_inicio <= puerto_fin;
}

bool Lista_puertos_valida(const std::vector<int>& puertos) {
    for (int puerto : puertos) {
        if (!Puerto_valido(puerto)) {
            return false;
        }
    }
    return !puertos.empty();
}

//ya toy harto 
//Excepciones para el timeout para mas que nada darle un limite de tiempo y que no se tarde demasiado (mas i es tcp puede durar eternamente esta cosa si se lo propone)
bool Timeout_valido(int timeout_ms){
    return timeout_ms > 0 && timeout_ms <= 30000; // entre 1 ms y 30 seg
}

// Para el sniffer
bool Interfaz_valida(const string &nombre_interfaz){ //ayuda a verficar que las interfaces sean validas
    pcap_if_t *todas_interfaces, *interfaz_actual;
    char buffer_error[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&todas_interfaces, buffer_error) == -1) return false;

    bool encontrada = false;
    for(interfaz_actual = todas_interfaces; interfaz_actual != nullptr; interfaz_actual = interfaz_actual->next){
        if(nombre_interfaz == interfaz_actual->name){
            encontrada = true;
            break;
        }
    }
    pcap_freealldevs(todas_interfaces);//libera el espacio donde se guardaban las interfaces esto para no perder recursos y que no se trabe
    return encontrada;
}
bool Snapvalido(int longitud_captura){
    return longitud_captura > 0 && longitud_captura <= 65535; //si el tamano enta entre 1 y 65535 entonces es valido
}
bool Filtrovalido(const string &filtro, pcap_t *manejador_pcap){//verifica la sintaxis del filtro antes de traducircelo 
    struct bpf_program programa_filtro;
    if(pcap_compile(manejador_pcap, &programa_filtro, filtro.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) return false;//intenta compilar el filtro si devuelve -1 tuvo errores si devuelve 0 entonces no tuvo 
    pcap_freecode(&programa_filtro); //libera la memoria de  los datos filtrados, ya que solo estamos validando todo antes de usarlo
    return true;
}
