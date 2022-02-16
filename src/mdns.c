
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#define MAX_SRV_COUNT 64
#define MAX_SOCKETS 32

#include <stdio.h>

#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#define sleep(x) Sleep(x * 1000)
#else
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "mdns.h"
#include "lxi.h"
#include "error.h"

static char entrybuffer[256];
static char namebuffer[256];

static struct sockaddr_in service_address_ipv4;
static struct sockaddr_in6 service_address_ipv6;

static int has_ipv4;
static int has_ipv6;

// Define struct to store services
typedef struct {
    const struct sockaddr* addr;
    size_t addrlen;
    char device_name[256];
    char service_type[256];
    int service_port;
    int fully_discovered;
} service_info_t;

typedef struct {
    lxi_info_t* info;
    service_info_t services[MAX_SRV_COUNT];
    int service_count;
    int* sockets;
    int* listening_sockets;
} lxi_store_t;

// Data for our service including the mDNS records
typedef struct {
    mdns_string_t service;
    mdns_string_t hostname;
    mdns_string_t service_instance;
    mdns_string_t hostname_qualified;
    struct sockaddr_in address_ipv4;
    struct sockaddr_in6 address_ipv6;
    int port;
    mdns_record_t record_ptr;
    mdns_record_t record_srv;
    mdns_record_t record_a;
    mdns_record_t record_aaaa;
    mdns_record_t txt_record[2];
} service_t;

static int query_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
                          uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
                          size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                          size_t record_length, void* user_data);

static mdns_string_t
ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr,
                       size_t addrlen) {
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST,
                          service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if (ret == 0) {
        len = snprintf(buffer, capacity, "%s", host);
    }
    if (len >= (int)capacity)
        len = (int)capacity - 1;
    mdns_string_t str;
    str.str = buffer;
    str.length = len;
    return str;
}

static mdns_string_t
ipv6_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in6* addr,
                       size_t addrlen) {
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST,
                          service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if (ret == 0) {
        len = snprintf(buffer, capacity, "%s", host);
    }
    if (len >= (int)capacity)
        len = (int)capacity - 1;
    mdns_string_t str;
    str.str = buffer;
    str.length = len;
    return str;
}

static mdns_string_t
ip_address_to_string(char* buffer, size_t capacity, const struct sockaddr* addr, size_t addrlen) {
    if (addr->sa_family == AF_INET6)
        return ipv6_address_to_string(buffer, capacity, (const struct sockaddr_in6*)addr, addrlen);
    return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in*)addr, addrlen);
}

static inline size_t
str_in_data(const char* data, char* s_to_search, size_t data_len) {
    int pos_search = 0;
    int pos_text = 0;
    int len_search = (int)strlen(s_to_search) - 1;
    for (pos_text = 0; pos_text < data_len;++pos_text)
    {
        if((data[pos_text] == s_to_search[pos_search]))
        {
            ++pos_search;
            if(pos_search == len_search)
            {
                // match
                return 0;
            }
        }
        else
        {
            pos_text -=pos_search;
            pos_search = 0;
        }
    }
    // no match
    return -1;
}

static void
finalize_service(lxi_store_t* lxistore, int service_id){
    char* service_type = "Unknown";
    if (strstr(lxistore->services[service_id].service_type, "_lxi._tcp") != NULL)
        service_type = "lxi";
    else if (strstr(lxistore->services[service_id].service_type, "_vxi-11._tcp") != NULL)
        service_type = "vxi-11";
    else if (strstr(lxistore->services[service_id].service_type, "_scpi-raw._tcp") != NULL)
        service_type = "scpi-raw";
    else if (strstr(lxistore->services[service_id].service_type, "_scpi-telnet._tcp") != NULL)
        service_type = "scpi-telnet";
    else if (strstr(lxistore->services[service_id].service_type, "_hislip._tcp") != NULL)
        service_type = "hislip";
    
    // Remove domain and type from device name
    char* str_name_end = strstr(lxistore->services[service_id].device_name, lxistore->services[service_id].service_type);
    if (str_name_end != NULL){
        lxistore->services[service_id].device_name[strlen(lxistore->services[service_id].device_name)-strlen(str_name_end) - 1] = '\0';
    }
    
    char ipbuf[INET6_ADDRSTRLEN];
    ip_address_to_string(ipbuf, INET6_ADDRSTRLEN, lxistore->services[service_id].addr, lxistore->services[service_id].addrlen);
    
    // Pass to callback
    lxistore->info->service(ipbuf, lxistore->services[service_id].device_name, service_type, lxistore->services[service_id].service_port);
    
    // Free the address that was allocated through malloc
    free((void *)lxistore->services[service_id].addr);
}

static int
get_service_info(int sock, const char* qry_str, int type, lxi_store_t* lxistore, int service_id){

    size_t internal_capacity = 2048;
    void* internal_buffer = malloc(internal_capacity);
    mdns_query_t query[1];
    int query_ptr_info_id;
    int res;
    
    // Prepare the query
    query[0].name = qry_str;
    query[0].type = type;
    query[0].length = strlen(query[0].name);
    
    query_ptr_info_id = mdns_multiquery_send(sock, query, 1, internal_buffer, internal_capacity, 0);
    if (query_ptr_info_id < 0)
        error_printf("Failed to send mDNS query: %s\n", strerror(errno));
    
    do {
        struct timeval timeout;
        // This timeout only applies to subqueries
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        
        fd_set readfs;
        FD_ZERO(&readfs);
        FD_SET(sock, &readfs);
        
        res = select(sock+1, &readfs, 0, 0, &timeout);
        if (res > 0 && FD_ISSET(sock, &readfs)){
            mdns_query_recv(sock, internal_buffer, internal_capacity, query_callback, lxistore, query_ptr_info_id);
        }
    } while (res > 0 && (lxistore->services[service_id].fully_discovered < 0));
    
    free(internal_buffer);
    return 0;
}

static int
get_service_id(lxi_store_t* lxistore, const struct sockaddr* from, mdns_string_t name)
{
    for (int i = 0; i < lxistore->service_count; i++){
        if (str_in_data((MDNS_STRING_FORMAT(name)), lxistore->services[i].service_type, strlen((MDNS_STRING_FORMAT(name)))))
            continue;
        if (lxistore->services[i].addr->sa_family == AF_INET && (((const struct sockaddr_in*)from)->sin_addr.s_addr == ((const struct sockaddr_in*)lxistore->services[i].addr)->sin_addr.s_addr))
            return i;
        if (lxistore->services[i].addr->sa_family == AF_INET6 && (0 == memcmp(((const struct sockaddr_in6*)from)->sin6_addr.s6_addr,((const struct sockaddr_in6*)lxistore->services[i].addr)->sin6_addr.s6_addr, sizeof(((const struct sockaddr_in6*)from)->sin6_addr))))
            return i;
    }
    return -1;
}

// Callback handling parsing answers to queries sent
static int
query_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
               size_t record_length, void* user_data) {
    (void)sizeof(sock);
    (void)sizeof(query_id);
    (void)sizeof(name_length);
    (void)sizeof(user_data);
    lxi_store_t* lxistore = user_data;
    
    // Always reset namebuffer else string will contain content from the previous callback if shorter
    memset(namebuffer, 0, sizeof(namebuffer));
    
    mdns_string_t entrystr = mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));

    if ((rtype == MDNS_RECORDTYPE_PTR) && (entry == MDNS_ENTRYTYPE_ANSWER)) {
        mdns_string_t namestr = mdns_record_parse_ptr(data, size, record_offset, record_length,
                                                      namebuffer, sizeof(namebuffer));
      
        if ((strstr((MDNS_STRING_FORMAT(namestr)), "_lxi._tcp") != NULL)
            || (strstr((MDNS_STRING_FORMAT(namestr)), "_vxi-11._tcp") != NULL)
            || (strstr((MDNS_STRING_FORMAT(namestr)), "_scpi-raw._tcp") != NULL)
            || (strstr((MDNS_STRING_FORMAT(namestr)), "_scpi-telnet._tcp") != NULL)
            || (strstr((MDNS_STRING_FORMAT(namestr)), "_hislip._tcp") != NULL)){
            
            int service_id = get_service_id(lxistore, from, namestr);
            if (service_id < 0){
                // A service was found
                char* service_type;
                if (strstr((MDNS_STRING_FORMAT(namestr)), "_lxi._tcp") != NULL)
                    service_type = "_lxi._tcp";
                else if (strstr((MDNS_STRING_FORMAT(namestr)), "_vxi-11._tcp") != NULL)
                    service_type = "_vxi-11._tcp";
                else if (strstr((MDNS_STRING_FORMAT(namestr)), "_scpi-raw._tcp") != NULL)
                    service_type = "_scpi-raw._tcp";
                else if (strstr((MDNS_STRING_FORMAT(namestr)), "_scpi-telnet._tcp") != NULL)
                    service_type = "_scpi-telnet._tcp";
                else if (strstr((MDNS_STRING_FORMAT(namestr)), "_hislip._tcp") != NULL)
                    service_type = "_hislip._tcp";
                
                // Store service in LXI store
                strncpy(lxistore->services[lxistore->service_count].service_type, service_type, strlen(service_type));
                lxistore->services[lxistore->service_count].addr = malloc(sizeof(const struct sockaddr));
                memcpy((void *)lxistore->services[lxistore->service_count].addr, (void *)from, sizeof(const struct sockaddr));
                lxistore->services[lxistore->service_count].addrlen = addrlen;
                lxistore->services[lxistore->service_count].service_type[strlen(service_type)] = '\0';
                lxistore->services[lxistore->service_count].service_port = 0;
                lxistore->services[lxistore->service_count].device_name[0] = '\0';
                lxistore->services[lxistore->service_count].fully_discovered = -1;
                lxistore->service_count++;
                
                // Do not use the socket bound to MDNS_PORT to query - use the other socket on the same interface
                int qry_sock = sock;
                for (int i = 0; i < MAX_SOCKETS; i++){
                    if (lxistore->listening_sockets[i] == sock){
                        qry_sock = lxistore->sockets[i];
                        break;
                    }
                }
                get_service_info(qry_sock, (MDNS_STRING_FORMAT(namestr)), MDNS_RECORDTYPE_PTR, lxistore, lxistore->service_count);
            }
            else if (strstr((MDNS_STRING_FORMAT(entrystr)), "_services") == NULL) {
                
                // PTR received with the device name
                strncpy(lxistore->services[service_id].device_name, (MDNS_STRING_FORMAT(namestr)), strlen((MDNS_STRING_FORMAT(namestr))));
                lxistore->services[service_id].device_name[strlen((MDNS_STRING_FORMAT(namestr)))] = '\0';
                
                // Do not use the socket bound to MDNS_PORT to query - use the other socket on the same interface
                int qry_sock = sock;
                for (int i = 0; i < MAX_SOCKETS; i++){
                    if (lxistore->listening_sockets[i] == sock){
                        qry_sock = lxistore->sockets[i];
                        break;
                    }
                }
                
                // Request for service information
                get_service_info(qry_sock, lxistore->services[service_id].device_name, MDNS_RECORDTYPE_SRV, lxistore, lxistore->service_count);
            }
        }
        
    }
    else if (rtype == MDNS_RECORDTYPE_SRV && lxistore->service_count) {
        // Receive SRV record - parse to get some service information
        mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
        int service_id = get_service_id(lxistore, from, entrystr);
    
        // SRV matches with a service found previously, service is now fully discovered
        if (service_id >= 0 && (lxistore->services[service_id].fully_discovered == -1)){
            lxistore->services[service_id].service_port=srv.port;
            lxistore->services[service_id].fully_discovered = 1;
            finalize_service(lxistore, service_id);
        };
    }
    
    return 0;
}

// Open sockets for sending one-shot multicast queries from an ephemeral port
static int
open_client_sockets(int* sockets, int* listening_sockets, int max_sockets, int port, lxi_info_t *info, int timeout, int num_sockets) {
    // When sending, each socket can only send to one network interface
    // Thus we need to open one socket for each interface and address family
    
#ifdef _WIN32
    
    IP_ADAPTER_ADDRESSES* adapter_address = 0;
    ULONG address_size = 8000;
    unsigned int ret;
    unsigned int num_retries = 4;
    do {
        adapter_address = (IP_ADAPTER_ADDRESSES*)malloc(address_size);
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0,
                                   adapter_address, &address_size);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            free(adapter_address);
            adapter_address = 0;
            address_size *= 2;
        } else {
            break;
        }
    } while (num_retries-- > 0);
    
    if (!adapter_address || (ret != NO_ERROR)) {
        free(adapter_address);
        error_printf("Failed to get network adapter addresses\n");
        return num_sockets;
    }
    
    int first_ipv4 = 1;
    int first_ipv6 = 1;
    for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
        if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
            continue;
        if (adapter->OperStatus != IfOperStatusUp)
            continue;
        
        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in* saddr = (struct sockaddr_in*)unicast->Address.lpSockaddr;
                if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) ||
                    (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
                    (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) ||
                    (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
                    int log_addr = 0;
                    if (first_ipv4) {
                        service_address_ipv4 = *saddr;
                        first_ipv4 = 0;
                        log_addr = 1;
                    }
                    has_ipv4 = 1;
                    if (num_sockets < max_sockets) {
                        saddr->sin_port = htons((unsigned short)port);
                        int sock = mdns_socket_open_ipv4(saddr);
                        if (sock >= 0) {
                            sockets[num_sockets] = sock;
                            // For each opened socket, also open a listening socket on 5353 as response may not come to the querying port
                            saddr->sin_port = htons(MDNS_PORT);
                            int lsock = mdns_socket_open_ipv4(saddr);
                            if (lsock >= 0) {
                                listening_sockets[num_sockets++] = lsock;
                                log_addr = 1;
                            } else {
                                log_addr = 0;
                            }
                        } else {
                            log_addr = 0;
                        }
                    }
                    if (log_addr) {
                        // Notify current broadcast address and network interface via callback
                        if (info->broadcast != NULL){
                            info->broadcast(inet_ntoa(saddr->sin_addr), adapter->FriendlyName);
                        }
                    }
                }
            } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                struct sockaddr_in6* saddr = (struct sockaddr_in6*)unicast->Address.lpSockaddr;
                // Ignore link-local addresses
                //if (saddr->sin6_scope_id)
                //    continue;
                static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 1};
                static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
                    0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
                if ((unicast->DadState == NldsPreferred) &&
                    memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
                    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
                    int log_addr = 0;
                    if (first_ipv6) {
                        service_address_ipv6 = *saddr;
                        first_ipv6 = 0;
                        log_addr = 1;
                    }
                    has_ipv6 = 1;
                    if (num_sockets < max_sockets) {
                        saddr->sin6_port = htons((unsigned short)port);
                        int sock = mdns_socket_open_ipv6(saddr);
                        if (sock >= 0) {
                            sockets[num_sockets] = sock;
                            // For each opened socket, also open a listening socket on 5353 as response may not come to the querying port
                            saddr->sin6_port = htons(MDNS_PORT);
                            int lsock = mdns_socket_open_ipv6(saddr);
                            if (lsock >= 0) {
                                listening_sockets[num_sockets++] = lsock;
                                log_addr = 1;
                            } else {
                                log_addr = 0;
                            }
                        } else {
                            log_addr = 0;
                        }
                    }
                    if (log_addr) {
                        char addr_s[INET6_ADDRSTRLEN];
                        // Notify current broadcast address and network interface via callback
                        inet_ntop(AF_INET6, &saddr->sin6_addr, addr_s, INET6_ADDRSTRLEN);
                        if (info->broadcast != NULL){
                            info->broadcast(addr_s, adapter->FriendlyName);
                        }
                    }
                }
            }
        }
    }
    
    free(adapter_address);
    
#else
    
    struct ifaddrs* ifaddr = 0;
    struct ifaddrs* ifa = 0;
    
    if (getifaddrs(&ifaddr) < 0)
        error_printf("Unable to get interface addresses\n");

    int first_ipv4 = 1;
    int first_ipv6 = 1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
            continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
            continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* saddr = (struct sockaddr_in*)ifa->ifa_addr;
            if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                int log_addr = 0;
                if (first_ipv4) {
                    service_address_ipv4 = *saddr;
                    first_ipv4 = 0;
                    log_addr = 1;
                }
                has_ipv4 = 1;
                if (num_sockets < max_sockets) {
                    saddr->sin_port = htons(port);
                    int sock = mdns_socket_open_ipv4(saddr, ifa->ifa_name);
                    if (sock >= 0) {
                        sockets[num_sockets] = sock;
                        // For each opened socket, also open a listening socket on 5353 as response may not come to the querying port
                        saddr->sin_port = htons(MDNS_PORT);
                        int lsock = mdns_socket_open_ipv4(saddr, ifa->ifa_name);
                        if (lsock >= 0) {
                            listening_sockets[num_sockets++] = lsock;
                            log_addr = 1;
                        } else {
                            log_addr = 0;
                        }
                    } else {
                        log_addr = 0;
                    }
                }
                if (log_addr) {
                    // Notify current broadcast address and network interface via callback
                    if (info->broadcast != NULL){
                        info->broadcast(inet_ntoa(saddr->sin_addr), ifa->ifa_name);
                    }
                }
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6* saddr = (struct sockaddr_in6*)ifa->ifa_addr;
            // Ignore link-local addresses
            //if (saddr->sin6_scope_id)
            //    continue;
            static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1};
            static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
                0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
            if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
                memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
                int log_addr = 0;
                if (first_ipv6) {
                    service_address_ipv6 = *saddr;
                    first_ipv6 = 0;
                    log_addr = 1;
                }
                has_ipv6 = 1;
                if (num_sockets < max_sockets) {
                    saddr->sin6_port = htons(port);
                    int sock = mdns_socket_open_ipv6(saddr, ifa->ifa_name);
                    if (sock >= 0) {
                        sockets[num_sockets] = sock;
                        // For each opened socket, also open a listening socket on 5353 as response may not come to the querying port
                        saddr->sin6_port = htons(MDNS_PORT);
                        int lsock = mdns_socket_open_ipv6(saddr, ifa->ifa_name);
                        if (lsock >= 0) {
                            listening_sockets[num_sockets++] = lsock;
                            log_addr = 1;
                        } else {
                            log_addr = 0;
                        }
                    } else {
                        log_addr = 0;
                    }
                }
                if (log_addr) {
                    char addr_s[INET6_ADDRSTRLEN];
                    // Notify current broadcast address and network interface via callback
                    inet_ntop(AF_INET6, &saddr->sin6_addr, addr_s, INET6_ADDRSTRLEN);
                    if (info->broadcast != NULL){
                        info->broadcast(addr_s, ifa->ifa_name);
                    }
                }
            }
        }
    }
    
    freeifaddrs(ifaddr);
    
#endif
    
    return num_sockets;
}

// Send a DNS-SD query
static int
send_dns_sd(lxi_store_t lxistore, int timeout_user){
    int sockets[MAX_SOCKETS];
    int listening_sockets[MAX_SOCKETS];
    
    int num_sockets = open_client_sockets(sockets, listening_sockets, sizeof(sockets) / sizeof(sockets[0]), 0, lxistore.info, timeout_user, 0);
    if (num_sockets <= 0) {
        error_printf("Failed to open any client sockets\n");
        return -1;
    }
       
    for (int isock = 0; isock < num_sockets; ++isock) {
        if (mdns_discovery_send(sockets[isock])){
            error_printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
        }
    }
    
    size_t capacity = 2048;
    void* buffer = malloc(capacity);
    
    void* user_data = &lxistore;
    lxistore.sockets = sockets;
    lxistore.listening_sockets = listening_sockets;
    
    size_t records;
    
    int res;
    do {
        struct timeval timeout;
        timeout.tv_sec = timeout_user / 1000;
        timeout.tv_usec = 1000 * (timeout_user % 1000);
        
        int nfds = 0;
        fd_set readfs;
        FD_ZERO(&readfs);
        for (int isock = 0; isock < num_sockets; ++isock) {
            if (sockets[isock] >= nfds)
                nfds = sockets[isock] + 1;
            if (listening_sockets[isock] >= nfds)
                nfds = listening_sockets[isock] + 1;
            FD_SET(sockets[isock], &readfs);
            FD_SET(listening_sockets[isock], &readfs);
        }
        
        records = 0;
        res = select(nfds, &readfs, 0, 0, &timeout);
        if (res > 0) {
            for (int isock = 0; isock < num_sockets; ++isock) {
                if (FD_ISSET(sockets[isock], &readfs)) {
                    records += mdns_socket_listen(sockets[isock], buffer, capacity, query_callback,
                                                  user_data);
                }
                if (FD_ISSET(listening_sockets[isock], &readfs)) {
                    records += mdns_socket_listen(listening_sockets[isock], buffer, capacity, query_callback,
                                                  user_data);
                }
            }
        }
    } while (res > 0);
    
    free(buffer);
    
    for (int isock = 0; isock < num_sockets; ++isock)
        mdns_socket_close(sockets[isock]);
    
    return 0;
}

int mdns_discover(lxi_info_t *info, int timeout){
    
#ifdef _WIN32
    
    WORD versionWanted = MAKEWORD(1, 1);
    WSADATA wsaData;
    if (WSAStartup(versionWanted, &wsaData)) {
        error_printf("Failed to initialize WinSock\n");
        return -1;
    }
    
#endif
    int ret;
    lxi_store_t lxistore;
    lxistore.service_count = 0;
    lxistore.info = info;
    ret = send_dns_sd(lxistore, timeout);
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
