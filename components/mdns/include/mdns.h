// Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#ifndef ESP_MDNS_H_
#define ESP_MDNS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <tcpip_adapter.h>

#include "lwip/netif.h"


/* dns.h */
#define SIZEOF_DNS_HDR 12
#define DNS_FLAG1_RESPONSE        0x80
/*
Should be in dns.h endpoint_specified
*/


/* netif.h */
#define netif_set_client_data(netif, id, data) netif_get_client_data(netif, id) = (data)
#define netif_get_client_data(netif, id)       (netif)->client_data[(id)]
/* netif.h */

/* Global */
#define MDNS_DEBUG 0

#define TOPDOMAIN_LOCAL "local"
#define DNS_RRTYPE_AAAA           28    /* IPv6 address */
#define DNS_RRTYPE_SRV            33
#define DNS_RRTYPE_TXT            16
#define SRV_WEIGHT   0

#define DOMAIN_JUMP_SIZE 2
#define DOMAIN_JUMP 0xc000
#define SRV_PRIORITY 0
#define MDNS_LABEL_MAXLEN  63
/** Description of a host/netif */

#define MDNS_DOMAIN_MAXLEN 256
#define DNS_RRCLASS_IN            1     /* the Internet */
#define DNS_RRCLASS_CS            2     /* the CSNET class (Obsolete - used only for examples in some obsolete RFCs) */
#define DNS_RRCLASS_CH            3     /* the CHAOS class */
#define DNS_RRCLASS_HS            4     /* Hesiod [Dyer 87] */
#define DNS_RRCLASS_ANY           255   /* any class */
#define DNS_RRCLASS_FLUSH         0x800 /* Flush bit */

#define MDNS_MAX_SERVICES               1
#define MDNS_READNAME_ERROR 0xFFFF
#define MDNS_LABEL_MAXLEN  63
#define NUM_DOMAIN_OFFSETS 10
#define REVERSE_PTR_V6_DOMAIN "ip6"
#define REVERSE_PTR_TOPDOMAIN "arpa"
#define REVERSE_PTR_V4_DOMAIN "in-addr"

#define REPLY_HOST_PTR_V6       0x08

#define DNS_RRTYPE_A              1     /* a host address */

/* Lookup from hostname -> IPv4 */
#define REPLY_HOST_A            0x01
/* Lookup from IPv4/v6 -> hostname */
#define REPLY_HOST_PTR_V4       0x02
/* Lookup from hostname -> IPv6 */
#define REPLY_HOST_AAAA         0x04
/* Lookup from hostname -> IPv6 */
#define REPLY_HOST_PTR_V6       0x08

/* Lookup for service types */
#define REPLY_SERVICE_TYPE_PTR  0x10
/* Lookup for instances of service */
#define REPLY_SERVICE_NAME_PTR  0x20
/* Lookup for location of service instance */
#define REPLY_SERVICE_SRV       0x40
/* Lookup for text info on service instance */
#define REPLY_SERVICE_TXT       0x80

#define netif_set_client_data(netif, id, data) netif_get_client_data(netif, id) = (data)


#define DNS_RRTYPE_PTR            12    /* a domain name pointer */
#define DNS_RRTYPE_ANY            255   /* any type */

#define MDNS_TTL  255
#define MDNS_PORT 5353
#define OUTPACKET_SIZE 500
#define DNS_FLAG1_AUTHORATIVE     0x04
static struct udp_pcb *mdns_pcb;
#define LWIP_MAKEU32(a,b,c,d) (((u32_t)((a) & 0xff) << 24) | \
                               ((u32_t)((b) & 0xff) << 16) | \
                               ((u32_t)((c) & 0xff) << 8)  | \
                                (u32_t)((d) & 0xff))
#define IPADDR6_INIT_HOST(a, b, c, d) { { { { PP_HTONL(a), PP_HTONL(b), PP_HTONL(c), PP_HTONL(d) } } }, IPADDR_TYPE_V6 }
#define IPADDR4_INIT_BYTES(a,b,c,d)   IPADDR4_INIT(PP_HTONL(LWIP_MAKEU32(a,b,c,d)))

#define DNS_HDR_GET_OPCODE(hdr) ((((hdr)->flags1) >> 3) & 0xF)
#define DNS_MQUERY_IPV4_GROUP_INIT  IPADDR4_INIT_BYTES(224,0,0,251)
#define DNS_MQUERY_IPV6_GROUP_INIT  IPADDR6_INIT_HOST(0xFF020000,0,0,0xFB)
#if LWIP_IPV4
const ip_addr_t dns_mquery_v4group = DNS_MQUERY_IPV4_GROUP_INIT;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
const ip_addr_t dns_mquery_v6group = DNS_MQUERY_IPV6_GROUP_INIT;
#endif /* LWIP_IPV6 */


struct mdns_domain {
  /* Encoded domain name */
  u8_t name[MDNS_DOMAIN_MAXLEN];
  /* Total length of domain name, including zero */
  u16_t length;
  /* Set if compression of this domain is not allowed */
  u8_t skip_compression;
};
// struct mdns_rr_info {
//   struct mdns_domain domain;
//   u16_t type;
//   u16_t klass;
// };

/** DNS message header */
struct dns_hdr {
  PACK_STRUCT_FIELD(u16_t id);
  PACK_STRUCT_FLD_8(u8_t flags1);
  PACK_STRUCT_FLD_8(u8_t flags2);
  PACK_STRUCT_FIELD(u16_t numquestions);
  PACK_STRUCT_FIELD(u16_t numanswers);
  PACK_STRUCT_FIELD(u16_t numauthrr);
  PACK_STRUCT_FIELD(u16_t numextrarr);
} PACK_STRUCT_STRUCT;

enum mdns_sd_proto {
  DNSSD_PROTO_UDP = 0,
  DNSSD_PROTO_TCP = 1
};



struct mdns_service;
typedef void (*service_get_txt_fn_t)(struct mdns_service *service, void *txt_userdata);

void mdns_resp_init(void);

err_t mdns_resp_add_netif(struct netif *netif, const char *hostname, u32_t dns_ttl);
err_t mdns_resp_remove_netif(struct netif *netif);

err_t mdns_resp_add_service(struct netif *netif, const char *name, const char *service, enum mdns_sd_proto proto, u16_t port, u32_t dns_ttl, service_get_txt_fn_t txt_fn, void *txt_userdata);
err_t mdns_resp_add_service_txtitem(struct mdns_service *service, const char *txt, u8_t txt_len);
void mdns_resp_netif_settings_changed(struct netif *netif);




// struct mdns_host {
//   /** Hostname */
//   char name[MDNS_LABEL_MAXLEN + 1];
//   /** Pointer to services */
//   struct mdns_service *services[MDNS_MAX_SERVICES];
//   /** TTL in seconds of A/AAAA/PTR replies */
//   u32_t dns_ttl;
// };

// /** Description of a service */
// struct mdns_service {
//   /** TXT record to answer with */
//   struct mdns_domain txtdata;
//   /** Name of service, like 'myweb' */
//   char name[MDNS_LABEL_MAXLEN + 1];
//   /** Type of service, like '_http' */
//   char service[MDNS_LABEL_MAXLEN + 1];
//   /** Callback function and userdata
//    * to update txtdata buffer */
//   service_get_txt_fn_t txt_fn;
//   void *txt_userdata;
//   /** TTL in seconds of SRV/TXT replies */
//   u32_t dns_ttl;
//   /** Protocol, TCP or UDP */
//   u16_t proto;
//   /** Port of the service */
//   u16_t port;
// };

// struct mdns_question {
//   struct mdns_rr_info info;
//   /** unicast reply requested */
//   u16_t unicast;
// };


// static const char *dnssd_protos[] = {
//     "_udp", /* DNSSD_PROTO_UDP */
//     "_tcp", /* DNSSD_PROTO_TCP */
// };


#ifdef __cplusplus
}
#endif
#endif
