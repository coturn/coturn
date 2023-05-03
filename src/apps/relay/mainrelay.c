/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "mainrelay.h"
#include "dbdrivers/dbdriver.h"

#include "prom_server.h"

#if defined(WINDOWS)
#include <iphlpapi.h>

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#endif

#if (!defined OPENSSL_VERSION_1_1_1)
#define OPENSSL_VERSION_1_1_1 0x10101000L
#endif

////// TEMPORARY data //////////

static int use_lt_credentials = 0;
static int anon_credentials = 0;
// long term credential
static int use_ltc = 0;
// timelimited long term credential
static int use_tltc = 0;

////// ALPN //////////

#if ALPN_SUPPORTED

char STUN_ALPN[128] = "stun.nat-discovery";
char TURN_ALPN[128] = "stun.turn";
char HTTP_ALPN[128] = "http/1.1";

#endif

////// TURNDB //////////////

#if defined(Q)
#undef Q
#endif

#define Q(x) #x

#if defined(QUOTE)
#undef QUOTE
#endif

#define QUOTE(x) Q(x)

#define DEFAULT_USERDB_FILE QUOTE(TURNDB)

//////TURN PARAMS STRUCTURE DEFINITION //////

#define DEFAULT_GENERAL_RELAY_SERVERS_NUMBER (1)

turn_params_t turn_params = {
    //////////////// OpenSSL group //////////////////////
    NULL,    /* tls_ctx */
    NULL,    /* dtls_ctx */
    DH_2066, /*dh_key_size*/

    "", /*cipher_list*/
    "", /*ec_curve_name*/

    "",                     /*ca_cert_file*/
    "turn_server_cert.pem", /*cert_file*/
    "turn_server_pkey.pem", /*pkey_file*/
    "",                     /*tls_password*/
    "",                     /*dh_file*/

    0, /*no_tlsv1*/
    0, /*no_tlsv1_1*/
    0, /*no_tlsv1_2*/
       /*no_tls*/
#if !TLS_SUPPORTED
    1,
#else
    0,
#endif
/*no_dtls*/
#if !DTLS_SUPPORTED
    1,
#else
    0,
#endif

    NULL,      /*tls_ctx_update_ev*/
    {0, NULL}, /*tls_mutex*/

    //////////////// Common params ////////////////////
    TURN_VERBOSE_NONE, /* verbose */
    0,                 /* turn_daemon */
    0,                 /* no_software_attribute */
    0,                 /* web_admin_listen_on_workers */

    0, /* do_not_use_config_file */

    "/var/run/turnserver.pid", /* pidfile */
    "",                        /* acme_redirect */

    ////////////////  Listener server /////////////////

    DEFAULT_STUN_PORT,     /* listener_port*/
    DEFAULT_STUN_TLS_PORT, /* tls_listener_port */
    0,                     /* alt_listener_port */
    0,                     /* alt_tls_listener_port */
    0,                     /* tcp_proxy_port */
    1,                     /* rfc5780 */

    0, /* no_udp */
    0, /* no_tcp */
    0, /* tcp_use_proxy */

    0, /* no_tcp_relay */
    0, /* no_udp_relay */

    "", /*listener_ifname*/

    {"", ""},                                                                 /*redis_statsdb*/
    0,                                                                        /*use_redis_statsdb*/
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, NULL, NULL, NULL}, /*listener*/
    {NULL, 0},                                                                /*ip_whitelist*/
    {NULL, 0},                                                                /*ip_blacklist*/
    NEV_UNKNOWN,                                                              /*net_engine_version*/
    {"Unknown", "UDP listening socket per session", "UDP thread per network endpoint",
     "UDP thread per CPU core"}, /*net_engine_version_txt*/

    //////////////// Relay servers //////////////////////////////////
    LOW_DEFAULT_PORTS_BOUNDARY,  /*min_port*/
    HIGH_DEFAULT_PORTS_BOUNDARY, /*max_port*/

    0, /*check_origin*/

    0, /*no_multicast_peers*/
    0, /*allow_loopback_peers*/

    "",   /*relay_ifname*/
    0,    /*relays_number*/
    NULL, /*relay_addrs*/
    0,    /*default_relays*/

    NULL,                                 /*external_ip*/
    DEFAULT_GENERAL_RELAY_SERVERS_NUMBER, /*general_relay_servers_number*/
    0,                                    /*udp_relay_servers_number*/

    ////////////// Auth server /////////////////////////////////////
    "",
    "",
    0,

    /////////////// AUX SERVERS ////////////////
    {NULL, 0, {0, NULL}}, /*aux_servers_list*/
    0,                    /*udp_self_balance*/

    /////////////// ALTERNATE SERVERS ////////////////
    {NULL, 0, {0, NULL}}, /*alternate_servers_list*/
    {NULL, 0, {0, NULL}}, /*tls_alternate_servers_list*/

    /////////////// stop server ////////////////
    0, /*stop_turn_server*/

    /////////////// MISC PARAMS ////////////////
    0,                                  /* stun_only */
    0,                                  /* no_stun */
    0,                                  /* secure_stun */
    0,                                  /* server_relay */
    0,                                  /* fingerprint */
    ':',                                /* rest_api_separator */
    STUN_DEFAULT_NONCE_EXPIRATION_TIME, /* stale_nonce */
    STUN_DEFAULT_MAX_ALLOCATE_LIFETIME, /* max_allocate_lifetime */
    STUN_DEFAULT_CHANNEL_LIFETIME,      /* channel_lifetime */
    STUN_DEFAULT_PERMISSION_LIFETIME,   /* permission_lifetime */
    0,                                  /* mobility */
    TURN_CREDENTIALS_NONE,              /* ct */
    0,                                  /* use_auth_secret_with_timestamp */
    0,                                  /* max_bps */
    0,                                  /* bps_capacity */
    0,                                  /* bps_capacity_allocated */
    0,                                  /* total_quota */
    0,                                  /* user_quota */
    0,                                  /* prometheus disabled by default */
    DEFAULT_PROM_SERVER_PORT,           /* prometheus port */
    0, /* prometheus username labelling disabled by default when prometheus is enabled */

    ///////////// Users DB //////////////
    {(TURN_USERDB_TYPE)0, {"\0", "\0"}, {0, NULL, {NULL, 0}}},

    ///////////// CPUs //////////////////
    DEFAULT_CPUS_NUMBER,

    ///////// Encryption /////////
    "",                                     /* secret_key_file */
    "",                                     /* secret_key */
    ALLOCATION_DEFAULT_ADDRESS_FAMILY_IPV4, /* allocation_default_address_family */
    0,                                      /* no_auth_pings */
    0,                                      /* no_dynamic_ip_list */
    0,                                      /* no_dynamic_realms */

    0, /* log_binding */
    0, /* no_stun_backward_compatibility */
    0  /* response_origin_only_with_rfc5780 */
};

//////////////// OpenSSL Init //////////////////////

static void openssl_setup(void);

/*
 * openssl genrsa -out pkey 2048
 * openssl req -new -key pkey -out cert.req
 * openssl x509 -req -days 365 -in cert.req -signkey pkey -out cert
 *
 */

//////////// Common static process params ////////
#if defined(WINDOWS)
// TODO: implement it!!!
#else
static gid_t procgroupid = 0;
static uid_t procuserid = 0;
static gid_t procgroupid_set = 0;
static uid_t procuserid_set = 0;
static char procusername[1025] = "\0";
static char procgroupname[1025] = "\0";
#endif

////////////// Configuration functionality ////////////////////////////////

static void read_config_file(int argc, char **argv, int pass);
static void reload_ssl_certs(evutil_socket_t sock, short events, void *args);

static void shutdown_handler(evutil_socket_t sock, short events, void *args);

//////////////////////////////////////////////////

static int make_local_listeners_list(void) {
  int ret = 0;
#if defined(WINDOWS)

  DWORD dwSize = 0;
  DWORD dwRetVal = 0;

  unsigned int i = 0;

  // Set the flags to pass to GetAdaptersAddresses
  ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

  // default to unspecified address family (both)
  ULONG family = AF_UNSPEC;

  LPVOID lpMsgBuf = NULL;

  PIP_ADAPTER_ADDRESSES pAddresses = NULL;
  ULONG outBufLen = 0;
  ULONG Iterations = 0;

  PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
  PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
  PIP_ADAPTER_ANYCAST_ADDRESS pAnycast = NULL;
  PIP_ADAPTER_MULTICAST_ADDRESS pMulticast = NULL;
  IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;
  IP_ADAPTER_PREFIX *pPrefix = NULL;

  // Allocate a 15 KB buffer to start with.
  outBufLen = WORKING_BUFFER_SIZE;

  do {

    pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
    if (pAddresses == NULL) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
      return -1;
    }

    dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      FREE(pAddresses);
      pAddresses = NULL;
    } else {
      break;
    }

    Iterations++;

  } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

  if (dwRetVal == NO_ERROR) {
    // If successful, output some information from the data we received
    pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
      /*
      printf("\tLength of the IP_ADAPTER_ADDRESS struct: %ld\n",
          pCurrAddresses->Length);
      printf("\tIfIndex (IPv4 interface): %u\n", pCurrAddresses->IfIndex);
      printf("\tAdapter name: %s\n", pCurrAddresses->AdapterName);//*/

      pUnicast = pCurrAddresses->FirstUnicastAddress;
      if (pUnicast != NULL) {
        // printf("\tNumber of Unicast Addresses:\n");
        for (i = 0; pUnicast != NULL; pUnicast = pUnicast->Next) {
          char saddr[INET6_ADDRSTRLEN] = "";
          if (AF_INET == pUnicast->Address.lpSockaddr->sa_family) // IPV4
          {
            if (!inet_ntop(PF_INET, &((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr, saddr,
                           INET6_ADDRSTRLEN))
              continue;
            if (strstr(saddr, "169.254.") == saddr)
              continue;
            if (!strcmp(saddr, "0.0.0.0"))
              continue;
          } else if (AF_INET6 == pUnicast->Address.lpSockaddr->sa_family) // IPV6
          {
            if (!inet_ntop(PF_INET6, &((struct sockaddr_in6 *)pUnicast->Address.lpSockaddr)->sin6_addr, saddr,
                           INET6_ADDRSTRLEN))
              continue;
            if (strstr(saddr, "fe80") == saddr)
              continue;
            if (!strcmp(saddr, "::"))
              continue;
          } else
            continue;

          // printf("\t\tIP: %s\n", saddr);

          add_listener_addr(saddr);

          if (MIB_IF_TYPE_LOOPBACK != pCurrAddresses->IfType)
            ret++;
        }
      }
      /*
      else
          printf("\tNo Unicast Addresses\n");

      pAnycast = pCurrAddresses->FirstAnycastAddress;
      if (pAnycast) {
          for (i = 0; pAnycast != NULL; i++)
              pAnycast = pAnycast->Next;
          printf("\tNumber of Anycast Addresses: %d\n", i);
      }
      else
          printf("\tNo Anycast Addresses\n");

      pMulticast = pCurrAddresses->FirstMulticastAddress;
      if (pMulticast) {
          for (i = 0; pMulticast != NULL; i++)
              pMulticast = pMulticast->Next;
          printf("\tNumber of Multicast Addresses: %d\n", i);
      }
      else
          printf("\tNo Multicast Addresses\n");

      pDnServer = pCurrAddresses->FirstDnsServerAddress;
      if (pDnServer) {
          for (i = 0; pDnServer != NULL; i++)
              pDnServer = pDnServer->Next;
          printf("\tNumber of DNS Server Addresses: %d\n", i);
      }
      else
          printf("\tNo DNS Server Addresses\n");

      printf("\tDNS Suffix: %wS\n", pCurrAddresses->DnsSuffix);
      printf("\tDescription: %wS\n", pCurrAddresses->Description);
      printf("\tFriendly name: %wS\n", pCurrAddresses->FriendlyName);

      if (pCurrAddresses->PhysicalAddressLength != 0) {
          printf("\tPhysical address: ");
          for (i = 0; i < (int)pCurrAddresses->PhysicalAddressLength;
              i++) {
              if (i == (pCurrAddresses->PhysicalAddressLength - 1))
                  printf("%.2X\n",
                  (int)pCurrAddresses->PhysicalAddress[i]);
              else
                  printf("%.2X-",
                  (int)pCurrAddresses->PhysicalAddress[i]);
          }
      }
      printf("\tFlags: %ld\n", pCurrAddresses->Flags);
      printf("\tMtu: %lu\n", pCurrAddresses->Mtu);
      char* pType = NULL;

      switch (pCurrAddresses->IfType)
      {
      case MIB_IF_TYPE_ETHERNET:
          pType = "ETHERNET";
          break;
      case MIB_IF_TYPE_PPP:
          pType = "PPP";
          break;
      case MIB_IF_TYPE_LOOPBACK:
          pType = "LOOPBACK";
          break;
      case MIB_IF_TYPE_SLIP:
          pType = "ATM";
          break;
      case IF_TYPE_IEEE80211:
          pType = "WIFI";
          break;
      }
      printf("\tIfType: %ld (%s)\n", pCurrAddresses->IfType, pType);
      printf("\tOperStatus: %ld\n", pCurrAddresses->OperStatus);
      printf("\tIpv6IfIndex (IPv6 interface): %u\n",
          pCurrAddresses->Ipv6IfIndex);
      printf("\tZoneIndices (hex): ");
      for (i = 0; i < 16; i++)
          printf("%lx ", pCurrAddresses->ZoneIndices[i]);
      printf("\n");

      printf("\tTransmit link speed: %I64u\n", pCurrAddresses->TransmitLinkSpeed);
      printf("\tReceive link speed: %I64u\n", pCurrAddresses->ReceiveLinkSpeed);

      pPrefix = pCurrAddresses->FirstPrefix;
      if (pPrefix) {
          for (i = 0; pPrefix != NULL; i++)
              pPrefix = pPrefix->Next;
          printf("\tNumber of IP Adapter Prefix entries: %d\n", i);
      }
      else
          printf("\tNumber of IP Adapter Prefix entries: 0\n");

      printf("\n");//*/

      pCurrAddresses = pCurrAddresses->Next;
    }
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Call to GetAdaptersAddresses failed with error: %d\n", dwRetVal);
    if (dwRetVal == ERROR_NO_DATA)
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "\tNo addresses were found for the requested parameters\n");
    else {

      if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        // Default language
                        (LPTSTR)&lpMsgBuf, 0, NULL)) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "\tError: %s", lpMsgBuf);
        LocalFree(lpMsgBuf);
        if (pAddresses)
          FREE(pAddresses);
        return -2;
      }
    }
  }

  if (pAddresses) {
    FREE(pAddresses);
  }

#else
  struct ifaddrs *ifs = NULL;
  struct ifaddrs *ifa = NULL;

  char saddr[INET6_ADDRSTRLEN] = "";

  if ((getifaddrs(&ifs) == 0) && ifs) {

    for (ifa = ifs; ifa != NULL; ifa = ifa->ifa_next) {

      if (!(ifa->ifa_flags & IFF_UP))
        continue;

      if (!(ifa->ifa_addr))
        continue;

      if (ifa->ifa_addr->sa_family == AF_INET) {
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, saddr, INET_ADDRSTRLEN))
          continue;
        if (strstr(saddr, "169.254.") == saddr)
          continue;
        if (!strcmp(saddr, "0.0.0.0"))
          continue;
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {
        if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, saddr, INET6_ADDRSTRLEN))
          continue;
        if (strstr(saddr, "fe80") == saddr)
          continue;
        if (!strcmp(saddr, "::"))
          continue;
      } else {
        continue;
      }

      add_listener_addr(saddr);

      if (!(ifa->ifa_flags & IFF_LOOPBACK))
        ret++;
    }
    freeifaddrs(ifs);
  }
#endif

  return ret;
}

static int make_local_relays_list(int allow_local, int family) {
  int counter = 0;

#if defined(WINDOWS)
  DWORD dwRetVal = 0;
  // Set the flags to pass to GetAdaptersAddresses
  ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

  // default to unspecified address family (both)
  ULONG fm = AF_UNSPEC;

  LPVOID lpMsgBuf = NULL;

  PIP_ADAPTER_ADDRESSES pAddresses = NULL;
  ULONG outBufLen = 0;
  ULONG Iterations = 0;

  PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
  PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;

  // Allocate a 15 KB buffer to start with.
  outBufLen = WORKING_BUFFER_SIZE;

  do {

    pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
    if (pAddresses == NULL) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
      return -1;
    }

    dwRetVal = GetAdaptersAddresses(fm, flags, NULL, pAddresses, &outBufLen);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      FREE(pAddresses);
      pAddresses = NULL;
    } else {
      break;
    }

    Iterations++;

  } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

  if (dwRetVal == NO_ERROR) {
    // If successful, output some information from the data we received
    pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
      /*
      printf("\tLength of the IP_ADAPTER_ADDRESS struct: %ld\n",
          pCurrAddresses->Length);
      printf("\tIfIndex (IPv4 interface): %u\n", pCurrAddresses->IfIndex);
      printf("\tAdapter name: %s\n", pCurrAddresses->AdapterName);//*/

      pUnicast = pCurrAddresses->FirstUnicastAddress;
      if (pUnicast != NULL) {
        // printf("\tNumber of Unicast Addresses:\n");
        for (; pUnicast != NULL; pUnicast = pUnicast->Next) {
          if (!allow_local && (MIB_IF_TYPE_LOOPBACK == pCurrAddresses->IfType))
            continue;

          char saddr[INET6_ADDRSTRLEN] = "";
          if (AF_INET == pUnicast->Address.lpSockaddr->sa_family) // IPV4
          {
            if (family != AF_INET)
              continue;
            if (!inet_ntop(PF_INET, &((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr, saddr,
                           INET6_ADDRSTRLEN))
              continue;
            if (strstr(saddr, "169.254.") == saddr)
              continue;
            if (!strcmp(saddr, "0.0.0.0"))
              continue;
          } else if (AF_INET6 == pUnicast->Address.lpSockaddr->sa_family) // IPV6
          {
            if (family != AF_INET6)
              continue;

            if (!inet_ntop(PF_INET6, &((struct sockaddr_in6 *)pUnicast->Address.lpSockaddr)->sin6_addr, saddr,
                           INET6_ADDRSTRLEN))
              continue;
            if (strstr(saddr, "fe80") == saddr)
              continue;
            if (!strcmp(saddr, "::"))
              continue;
          } else
            continue;

          if (add_relay_addr(saddr) > 0) {
            counter += 1;
          }
        }
      }
      pCurrAddresses = pCurrAddresses->Next;
    }
  }

  if (pAddresses) {
    FREE(pAddresses);
  }
#else
  struct ifaddrs *ifs = NULL;
  struct ifaddrs *ifa = NULL;

  char saddr[INET6_ADDRSTRLEN] = "";

  getifaddrs(&ifs);

  if (ifs) {
    for (ifa = ifs; ifa != NULL; ifa = ifa->ifa_next) {

      if (!(ifa->ifa_flags & IFF_UP))
        continue;

      if (!(ifa->ifa_name))
        continue;
      if (!(ifa->ifa_addr))
        continue;

      if (!allow_local && (ifa->ifa_flags & IFF_LOOPBACK))
        continue;

      if (ifa->ifa_addr->sa_family == AF_INET) {

        if (family != AF_INET)
          continue;

        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, saddr, INET_ADDRSTRLEN))
          continue;
        if (strstr(saddr, "169.254.") == saddr)
          continue;
        if (!strcmp(saddr, "0.0.0.0"))
          continue;
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {

        if (family != AF_INET6)
          continue;

        if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, saddr, INET6_ADDRSTRLEN))
          continue;
        if (strstr(saddr, "fe80") == saddr)
          continue;
        if (!strcmp(saddr, "::"))
          continue;
      } else
        continue;

      if (add_relay_addr(saddr) > 0) {
        counter += 1;
      }
    }
    freeifaddrs(ifs);
  }
#endif

  return counter;
}

int get_a_local_relay(int family, ioa_addr *relay_addr) {
  int ret = -1;
  int allow_local = 0;

#if defined(WINDOWS)
  DWORD dwRetVal = 0;
  // Set the flags to pass to GetAdaptersAddresses
  ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

  // default to unspecified address family (both)
  ULONG fm = AF_UNSPEC;

  LPVOID lpMsgBuf = NULL;

  PIP_ADAPTER_ADDRESSES pAddresses = NULL;
  ULONG outBufLen = 0;
  ULONG Iterations = 0;

  PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
  PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;

  outBufLen = WORKING_BUFFER_SIZE;

  do {

    pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
    if (pAddresses == NULL) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
      return -1;
    }

    dwRetVal = GetAdaptersAddresses(fm, flags, NULL, pAddresses, &outBufLen);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      FREE(pAddresses);
      pAddresses = NULL;
    } else {
      break;
    }

    Iterations++;

  } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

  if (dwRetVal == NO_ERROR) {
  galr_start:
    // If successful, output some information from the data we received
    pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
      pUnicast = pCurrAddresses->FirstUnicastAddress;
      if (pUnicast != NULL) {
        // printf("\tNumber of Unicast Addresses:\n");
        for (; pUnicast != NULL; pUnicast = pUnicast->Next) {
          if (!allow_local && (MIB_IF_TYPE_LOOPBACK == pCurrAddresses->IfType))
            continue;

          char saddr[INET6_ADDRSTRLEN] = "";
          if (AF_INET == pUnicast->Address.lpSockaddr->sa_family) // IPV4
          {
            if (family != AF_INET)
              continue;
            if (!inet_ntop(PF_INET, &((struct sockaddr_in *)pUnicast->Address.lpSockaddr)->sin_addr, saddr,
                           INET6_ADDRSTRLEN))
              continue;
            if (strstr(saddr, "169.254.") == saddr)
              continue;
            if (!strcmp(saddr, "0.0.0.0"))
              continue;
          } else if (AF_INET6 == pUnicast->Address.lpSockaddr->sa_family) // IPV6
          {
            if (family != AF_INET6)
              continue;

            if (!inet_ntop(PF_INET6, &((struct sockaddr_in6 *)pUnicast->Address.lpSockaddr)->sin6_addr, saddr,
                           INET6_ADDRSTRLEN))
              continue;
            if (strstr(saddr, "fe80") == saddr)
              continue;
            if (!strcmp(saddr, "::"))
              continue;
          } else
            continue;

          if (make_ioa_addr((const uint8_t *)saddr, 0, relay_addr) < 0) {
            continue;
          } else {
            ret = 0;
            break;
          }
        }
      }
      pCurrAddresses = pCurrAddresses->Next;
    }

    if (ret < 0 && !allow_local) {
      allow_local = 1;
      goto galr_start;
    }
  }

  if (pAddresses) {
    FREE(pAddresses);
  }
#else
  struct ifaddrs *ifs = NULL;

  char saddr[INET6_ADDRSTRLEN] = "";

  getifaddrs(&ifs);

  if (ifs) {

  galr_start :

  {
    struct ifaddrs *ifa = NULL;

    for (ifa = ifs; ifa != NULL; ifa = ifa->ifa_next) {

      if (!(ifa->ifa_flags & IFF_UP))
        continue;

      if (!(ifa->ifa_name))
        continue;
      if (!(ifa->ifa_addr))
        continue;

      if (!allow_local && (ifa->ifa_flags & IFF_LOOPBACK))
        continue;

      if (ifa->ifa_addr->sa_family == AF_INET) {

        if (family != AF_INET)
          continue;

        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, saddr, INET_ADDRSTRLEN))
          continue;
        if (strstr(saddr, "169.254.") == saddr)
          continue;
        if (!strcmp(saddr, "0.0.0.0"))
          continue;
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {

        if (family != AF_INET6)
          continue;

        if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, saddr, INET6_ADDRSTRLEN))
          continue;
        if (strstr(saddr, "fe80") == saddr)
          continue;
        if (!strcmp(saddr, "::"))
          continue;
      } else
        continue;

      if (make_ioa_addr((const uint8_t *)saddr, 0, relay_addr) < 0) {
        continue;
      } else {
        ret = 0;
        break;
      }
    }
  }

    if (ret < 0 && !allow_local) {
      allow_local = 1;
      goto galr_start;
    }

    freeifaddrs(ifs);
  }
  return -1;
#endif
}

//////////////////////////////////////////////////

static char Usage[] =
    "Usage: turnserver [options]\n"
    "Options:\n"
    " -d, --listening-device	<device-name>		Listener interface device (NOT RECOMMENDED. Optional, Linux "
    "only).\n"
    " -p, --listening-port		<port>		TURN listener port (Default: 3478).\n"
    "						Note: actually, TLS & DTLS sessions can connect to the \"plain\" TCP & "
    "UDP port(s), too,\n"
    "						if allowed by configuration.\n"
    " --tls-listening-port		<port>		TURN listener port for TLS & DTLS listeners\n"
    "						(Default: 5349).\n"
    "						Note: actually, \"plain\" TCP & UDP sessions can connect to the TLS & "
    "DTLS port(s), too,\n"
    "						if allowed by configuration. The TURN server\n"
    "						\"automatically\" recognizes the type of traffic. Actually, two "
    "listening\n"
    "						endpoints (the \"plain\" one and the \"tls\" one) are equivalent in "
    "terms of\n"
    "						functionality; but we keep both endpoints to satisfy the RFC 5766 "
    "specs.\n"
    "						For secure TCP connections, we currently support SSL version 3 and\n"
    "						TLS versions 1.0, 1.1 and 1.2. For secure UDP connections, we support\n"
    "						DTLS version 1.\n"
    " --alt-listening-port<port>	<port>		Alternative listening port for STUN CHANGE_REQUEST (in RFC "
    "5780 sense, \n"
    "                                                or in old RFC 3489 sense, default is \"listening port plus "
    "one\").\n"
    " --alt-tls-listening-port	<port>		Alternative listening port for TLS and DTLS,\n"
    " 						the default is \"TLS/DTLS port plus one\".\n"
    " --tcp-proxy-port		<port>		Support connections from TCP loadbalancer on this port. The "
    "loadbalancer should\n"
    "						use the binary proxy protocol "
    "(https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)\n"
    " -L, --listening-ip		<ip>		Listener IP address of relay server. Multiple listeners can be "
    "specified.\n"
    " --aux-server			<ip:port>	Auxiliary STUN/TURN server listening endpoint.\n"
    "						Auxiliary servers do not have alternative ports and\n"
    "						they do not support RFC 5780 functionality (CHANGE REQUEST).\n"
    "						Valid formats are 1.2.3.4:5555 for IPv4 and [1:2::3:4]:5555 for IPv6.\n"
    " --udp-self-balance				(recommended for older Linuxes only) Automatically balance UDP "
    "traffic\n"
    "						over auxiliary servers (if configured).\n"
    "						The load balancing is using the ALTERNATE-SERVER mechanism.\n"
    "						The TURN client must support 300 ALTERNATE-SERVER response for this "
    "functionality.\n"
    " -i, --relay-device		<device-name>	Relay interface device for relay sockets (NOT RECOMMENDED. "
    "Optional, Linux only).\n"
    " -E, --relay-ip		<ip>			Relay address (the local IP address that will be used to relay "
    "the\n"
    "						packets to the peer).\n"
    "						Multiple relay addresses may be used.\n"
    "						The same IP(s) can be used as both listening IP(s) and relay IP(s).\n"
    "						If no relay IP(s) specified, then the turnserver will apply the "
    "default\n"
    "						policy: it will decide itself which relay addresses to be used, and "
    "it\n"
    "						will always be using the client socket IP address as the relay IP "
    "address\n"
    "						of the TURN session (if the requested relay address family is the "
    "same\n"
    "						as the family of the client socket).\n"
    " -X, --external-ip  <public-ip[/private-ip]>	TURN Server public/private address mapping, if the server is "
    "behind NAT.\n"
    "						In that situation, if a -X is used in form \"-X ip\" then that ip will "
    "be reported\n"
    "						as relay IP address of all allocations. This scenario works only in a "
    "simple case\n"
    "						when one single relay address is be used, and no STUN CHANGE_REQUEST\n"
    "						functionality is required.\n"
    "						That single relay address must be mapped by NAT to the 'external' IP.\n"
    "						For that 'external' IP, NAT must forward ports directly (relayed port "
    "12345\n"
    "						must be always mapped to the same 'external' port 12345).\n"
    "						In more complex case when more than one IP address is involved,\n"
    "						that option must be used several times in the command line, each entry "
    "must\n"
    "						have form \"-X public-ip/private-ip\", to map all involved addresses.\n"
    " --allow-loopback-peers				Allow peers on the loopback addresses (127.x.x.x and ::1).\n"
    " --no-multicast-peers				Disallow peers on well-known broadcast addresses (224.0.0.0 "
    "and above, and FFXX:*).\n"
    " -m, --relay-threads		<number>	Number of relay threads to handle the established connections\n"
    "						(in addition to authentication thread and the listener thread).\n"
    "						If explicitly set to 0 then application runs in single-threaded mode.\n"
    "						If not set then a default OS-dependent optimal algorithm will be "
    "employed.\n"
    "						The default thread number is the number of CPUs.\n"
    "						In older systems (pre-Linux 3.9) the number of UDP relay threads "
    "always equals\n"
    "						the number of listening endpoints (unless -m 0 is set).\n"
    " --min-port			<port>		Lower bound of the UDP port range for relay endpoints "
    "allocation.\n"
    "						Default value is 49152, according to RFC 5766.\n"
    " --max-port			<port>		Upper bound of the UDP port range for relay endpoints "
    "allocation.\n"
    "						Default value is 65535, according to RFC 5766.\n"
    " -v, --verbose					'Moderate' verbose mode.\n"
    " -V, --Verbose					Extra verbose mode, very annoying (for debug purposes only).\n"
    " -o, --daemon					Start process as daemon (detach from current shell).\n"
    " --no-software-attribute	 		Production mode: hide the software version (formerly --prod).\n"
    " -f, --fingerprint				Use fingerprints in the TURN messages.\n"
    " -a, --lt-cred-mech				Use the long-term credential mechanism.\n"
    " -z, --no-auth					Do not use any credential mechanism, allow anonymous access.\n"
    " -u, --user			<user:pwd>	User account, in form 'username:password', for long-term "
    "credentials.\n"
    "						Cannot be used with TURN REST API.\n"
    " -r, --realm			<realm>		The default realm to be used for the users when no explicit\n"
    "						origin/realm relationship was found in the database.\n"
    "						Must be used with long-term credentials \n"
    "						mechanism or with TURN REST API.\n"
    " --check-origin-consistency			The flag that sets the origin consistency check:\n"
    "						across the session, all requests must have the same\n"
    "						main ORIGIN attribute value (if the ORIGIN was\n"
    "						initially used by the session).\n"
    " -q, --user-quota		<number>	Per-user allocation quota: how many concurrent allocations a user can "
    "create.\n"
    "						This option can also be set through the database, for a particular "
    "realm.\n"
    " -Q, --total-quota		<number>	Total allocations quota: global limit on concurrent allocations.\n"
    "						This option can also be set through the database, for a particular "
    "realm.\n"
    " -s, --max-bps			<number>	Default max bytes-per-second bandwidth a TURN session is "
    "allowed to handle\n"
    "						(input and output network streams are treated separately). Anything "
    "above\n"
    "						that limit will be dropped or temporary suppressed\n"
    "						(within the available buffer limits).\n"
    "						This option can also be set through the database, for a particular "
    "realm.\n"
    " -B, --bps-capacity		<number>	Maximum server capacity.\n"
    "						Total bytes-per-second bandwidth the TURN server is allowed to "
    "allocate\n"
    "						for the sessions, combined (input and output network streams are "
    "treated separately).\n"
    " -c				<filename>	Configuration file name (default - turnserver.conf).\n"
#if !defined(TURN_NO_SQLITE)
    " -b, , --db, --userdb	<filename>		SQLite database file name; default - /var/db/turndb or\n"
    "						    /usr/local/var/db/turndb or /var/lib/turn/turndb.\n"
#endif
#if !defined(TURN_NO_PQ)
    " -e, --psql-userdb, --sql-userdb <conn-string>	PostgreSQL database connection string, if used (default - "
    "empty, no PostgreSQL DB used).\n"
    "		                                This database can be used for long-term credentials mechanism users,\n"
    "		                                and it can store the secret value(s) for secret-based timed "
    "authentication in TURN REST API.\n"
    "						See http://www.postgresql.org/docs/8.4/static/libpq-connect.html for "
    "8.x PostgreSQL\n"
    "						versions format, see \n"
    "						"
    "http://www.postgresql.org/docs/9.2/static/libpq-connect.html#LIBPQ-CONNSTRING\n"
    "						for 9.x and newer connection string formats.\n"
#endif
#if !defined(TURN_NO_MYSQL)
    " -M, --mysql-userdb	<connection-string>	MySQL database connection string, if used (default - empty, no "
    "MySQL DB used).\n"
    "	                                	This database can be used for long-term credentials mechanism users,\n"
    "		                                and it can store the secret value(s) for secret-based timed "
    "authentication in TURN REST API.\n"
    "						The connection string my be space-separated list of parameters:\n"
    "	        	          		\"host=<ip-addr> dbname=<database-name> user=<database-user> "
    "\\\n							password=<database-user-password> port=<db-port> "
    "connect_timeout=<seconds> read_timeout=<seconds>\".\n\n"
    "						The connection string parameters for the secure communications (SSL):\n"
    "						ca, capath, cert, key, cipher\n"
    "						(see http://dev.mysql.com/doc/refman/5.1/en/ssl-options.html for the\n"
    "						command options description).\n\n"
    "	        	          		All connection-string parameters are optional.\n\n"
    " --secret-key-file	<filename>		This is the file path which contain secret key of aes encryption while "
    "using MySQL password encryption.\n"
    "						If you want to use in the MySQL connection string the password in "
    "encrypted format,\n"
    "						then set in this option the file path of the secret key. The key which "
    "is used to encrypt MySQL password.\n"
    "						Warning: If this option is set, then MySQL password must be set in "
    "\"mysql-userdb\" option in encrypted format!\n"
    "						If you want to use cleartext password then do not set this option!\n"
#endif
#if !defined(TURN_NO_MONGO)
    " -J, --mongo-userdb	<connection-string>	MongoDB connection string, if used (default - empty, no "
    "MongoDB used).\n"
    "	                                	This database can be used for long-term credentials mechanism users,\n"
    "		                                and it can store the secret value(s) for secret-based timed "
    "authentication in TURN REST API.\n"
#endif
#if !defined(TURN_NO_HIREDIS)
    " -N, --redis-userdb	<connection-string>	Redis user database connection string, if used (default - "
    "empty, no Redis DB used).\n"
    "	                                	This database can be used for long-term credentials mechanism users,\n"
    "		                                and it can store the secret value(s) for secret-based timed "
    "authentication in TURN REST API.\n"
    "						The connection string my be space-separated list of parameters:\n"
    "	        	          		\"host=<ip-addr> dbname=<db-number> \\\n			"
    "					password=<database-user-password> port=<db-port> "
    "connect_timeout=<seconds>\".\n\n"
    "	        	          		All connection-string parameters are optional.\n\n"
    " -O, --redis-statsdb	<connection-string>	Redis status and statistics database connection string, if "
    "used \n"
    "						(default - empty, no Redis stats DB used).\n"
    "	                                	This database keeps allocations status information, and it can be also "
    "used for publishing\n"
    "		                                and delivering traffic and allocation event notifications.\n"
    "						The connection string has the same parameters as redis-userdb "
    "connection string.\n"
#endif
#if !defined(TURN_NO_PROMETHEUS)
    " --prometheus					Enable prometheus metrics. It is disabled by default. If it is "
    "enabled it will listen on port 9641 under the path /metrics\n"
    "						also the path / on this port can be used as a health check\n"
    " --prometheus-port		<port>		Prometheus metrics port (Default: 9641).\n"
    " --prometheus-username-labels			When metrics are enabled, add labels with client usernames.\n"
#endif
    " --use-auth-secret				TURN REST API flag.\n"
    "						Flag that sets a special authorization option that is based upon "
    "authentication secret\n"
    "						(TURN Server REST API, see "
    "https://github.com/coturn/coturn/blob/master/README.turnserver).\n"
    "						This option is used with timestamp.\n"
    " --static-auth-secret		<secret>	'Static' authentication secret value (a string) for TURN REST "
    "API only.\n"
    "						If not set, then the turn server will try to use the 'dynamic' value\n"
    "						in turn_secret table in user database (if present).\n"
    "						That database value can be changed on-the-fly\n"
    "						by a separate program, so this is why it is 'dynamic'.\n"
    "						Multiple shared secrets can be used (both in the database and in the "
    "\"static\" fashion).\n"
    " --no-auth-pings				Disable periodic health checks to 'dynamic' auth secret tables.\n"
    " --no-dynamic-ip-list				Do not use dynamic allowed/denied peer ip list.\n"
    " --no-dynamic-realms				Do not use dynamic realm assignment and options.\n"
    " --server-name					Server name used for\n"
    "						the oAuth authentication purposes.\n"
    "						The default value is the realm name.\n"
    " --oauth					Support oAuth authentication.\n"
    " -n						Do not use configuration file, take all parameters from the "
    "command line only.\n"
    " --cert			<filename>		Certificate file, PEM format. Same file search rules\n"
    "						applied as for the configuration file.\n"
    "						If both --no-tls and --no_dtls options\n"
    "						are specified, then this parameter is not needed.\n"
    " --pkey			<filename>		Private key file, PEM format. Same file search rules\n"
    "						applied as for the configuration file.\n"
    "						If both --no-tls and --no-dtls options\n"
    " --pkey-pwd		<password>		If the private key file is encrypted, then this password to be "
    "used.\n"
    " --cipher-list		<cipher-string>		Allowed OpenSSL cipher list for TLS/DTLS connections.\n"
    "						Default value is \"DEFAULT\" for TLS/DTLS versions up to "
    "TLSv1.2/DTLSv1.2,\n"
    "						and the library default ciphersuites for TLSv1.3.\n"
    " --CA-file		<filename>		CA file in OpenSSL format.\n"
    "						Forces TURN server to verify the client SSL certificates.\n"
    "						By default, no CA is set and no client certificate check is "
    "performed.\n"
    " --ec-curve-name	<curve-name>		Curve name for EC ciphers, if supported by OpenSSL\n"
    "						library (TLS and DTLS). The default value is prime256v1,\n"
    "						if pre-OpenSSL 1.0.2 is used. With OpenSSL 1.0.2+,\n"
    "						an optimal curve will be automatically calculated, if not defined\n"
    "						by this option.\n"
    " --dh566					Use 566 bits predefined DH TLS key. Default size of the predefined key "
    "is 2066.\n"
    " --dh1066					Use 1066 bits predefined DH TLS key. Default size of the predefined "
    "key is 2066.\n"
    " --dh-file	<dh-file-name>			Use custom DH TLS key, stored in PEM format in the file.\n"
    "						Flags --dh566 and --dh1066 are ignored when the DH key is taken from a "
    "file.\n"
    " --no-tlsv1					Set TLSv1.1/DTLSv1.2 as a minimum supported protocol version.\n"
    "						With openssl-1.0.2 and below, do not allow "
    "TLSv1/DTLSv1 protocols.\n"
    " --no-tlsv1_1					Set TLSv1.2/DTLSv1.2 as a minimum supported protocol version.\n"
    "						With openssl-1.0.2 and below, do not allow TLSv1.1 "
    "protocol.\n"
    " --no-tlsv1_2					Set TLSv1.3/DTLSv1.2 as a minimum supported protocol version.\n"
    "						With openssl-1.0.2 and below, do not allow "
    "TLSv1.2/DTLSv1.2 protocols.\n"
    " --no-udp					Do not start UDP client listeners.\n"
    " --no-tcp					Do not start TCP client listeners.\n"
    " --no-tls					Do not start TLS client listeners.\n"
    " --no-dtls					Do not start DTLS client listeners.\n"
    " --no-udp-relay					Do not allow UDP relay endpoints, use only TCP relay option.\n"
    " --no-tcp-relay					Do not allow TCP relay endpoints, use only UDP relay options.\n"
    " -l, --log-file		<filename>		Option to set the full path name of the log file.\n"
    "						By default, the turnserver tries to open a log file in\n"
    "						/var/log/turnserver/, /var/log, /var/tmp, /tmp and . (current) "
    "directories\n"
    "						(which open operation succeeds first that file will be used).\n"
    "						With this option you can set the definite log file name.\n"
    "						The special names are \"stdout\" and \"-\" - they will force "
    "everything\n"
    "						to the stdout; and \"syslog\" name will force all output to the "
    "syslog.\n"
    " --no-stdout-log				Flag to prevent stdout log messages.\n"
    "						By default, all log messages are going to both stdout and to\n"
    "						a log file. With this option everything will be going to the log file "
    "only\n"
    "						(unless the log file itself is stdout).\n"
    " --syslog					Output all log information into the system log (syslog), do not use "
    "the file output.\n"
    " --syslog-facility             <value>          Set syslog facility for syslog messages. Default is ''.\n"
    " --simple-log					This flag means that no log file rollover will be used, and "
    "the log file\n"
    "						name will be constructed as-is, without PID and date appendage.\n"
    "						This option can be used, for example, together with the logrotate "
    "tool.\n"
    " --new-log-timestamp				Enable full ISO-8601 timestamp in all logs.\n"
    " --new-log-timestamp-format    	<format>	Set timestamp format (in strftime(1) format). Depends on "
    "--new-log-timestamp to be enabled.\n"
    " --log-binding					Log STUN binding request. It is now disabled by default to "
    "avoid DoS attacks.\n"
    " --stale-nonce[=<value>]			Use extra security with nonce value having limited lifetime (default "
    "600 secs).\n"
    " --max-allocate-lifetime	<value>		Set the maximum value for the allocation lifetime. Default to 3600 "
    "secs.\n"
    " --channel-lifetime		<value>		Set the lifetime for channel binding, default to 600 secs.\n"
    "						This value MUST not be changed for production purposes.\n"
    " --permission-lifetime		<value>		Set the value for the lifetime of the permission. Default to "
    "300 secs.\n"
    "						This MUST not be changed for production purposes.\n"
    " -S, --stun-only				Option to set standalone STUN operation only, all TURN requests will "
    "be ignored.\n"
    "     --no-stun					Option to suppress STUN functionality, only TURN requests will "
    "be processed.\n"
    " --alternate-server		<ip:port>	Set the TURN server to redirect the allocate requests (UDP and "
    "TCP services).\n"
    "						Multiple alternate-server options can be set for load balancing "
    "purposes.\n"
    "						See the docs for more information.\n"
    " --tls-alternate-server	<ip:port>		Set the TURN server to redirect the allocate requests (DTLS "
    "and TLS services).\n"
    "						Multiple alternate-server options can be set for load balancing "
    "purposes.\n"
    "						See the docs for more information.\n"
    " -C, --rest-api-separator	<SYMBOL>	This is the timestamp/username separator symbol (character) in TURN "
    "REST API.\n"
    "						The default value is ':'.\n"
    " --max-allocate-timeout=<seconds>		Max time, in seconds, allowed for full allocation establishment. "
    "Default is 60.\n"
    " --allowed-peer-ip=<ip[-ip]> 			Specifies an ip or range of ips that are explicitly allowed to "
    "connect to the \n"
    "						turn server. Multiple allowed-peer-ip can be set.\n"
    " --denied-peer-ip=<ip[-ip]> 			Specifies an ip or range of ips that are not allowed to "
    "connect to the turn server.\n"
    "						Multiple denied-peer-ip can be set.\n"
    " --pidfile <\"pid-file-name\">			File name to store the pid of the process.\n"
    "						Default is /var/run/turnserver.pid (if superuser account is used) or\n"
    "						/var/tmp/turnserver.pid .\n"
    " --acme-redirect <URL>				Redirect ACME, i.e. HTTP GET requests matching "
    "'^/.well-known/acme-challenge/(.*)' to '<URL>$1'.\n"
    "						Default is '', i.e. no special handling for such requests.\n"
    " --secure-stun					Require authentication of the STUN Binding request.\n"
    "						By default, the clients are allowed anonymous access to the STUN "
    "Binding functionality.\n"
    " --proc-user <user-name>			User name to run the turnserver process.\n"
    "						After the initialization, the turnserver process\n"
    "						will make an attempt to change the current user ID to that user.\n"
    " --proc-group <group-name>			Group name to run the turnserver process.\n"
    "						After the initialization, the turnserver process\n"
    "						will make an attempt to change the current group ID to that group.\n"
    " --mobility					Mobility with ICE (MICE) specs support.\n"
    " -K, --keep-address-family			Deprecated in favor of --allocation-default-address-family!!\n"
    "						TURN server allocates address family according TURN\n"
    "						Client <=> Server communication address family.\n"
    "						!! It breaks RFC6156 section-4.2 (violates default IPv4) !!\n"
    " -A --allocation-default-address-family=<ipv4|ipv6|keep> 		Default is IPv4\n"
    "						TURN server allocates address family according TURN client requested "
    "address family. \n"
    "						If address family is not requested explicitly by client, then it falls "
    "back to this default.\n"
    "						The standard RFC explicitly define actually that this default must be "
    "IPv4,\n"
    "						so use other option values with care!\n"
    " --no-cli					Turn OFF the CLI support. By default it is always ON.\n"
    " --cli-ip=<IP>					Local system IP address to be used for CLI server endpoint. "
    "Default value\n"
    "						is 127.0.0.1.\n"
    " --cli-port=<port>				CLI server port. Default is 5766.\n"
    " --cli-password=<password>			CLI access password. Default is empty (no password).\n"
    "						For the security reasons, it is recommended to use the encrypted\n"
    "						for of the password (see the -P command in the turnadmin utility).\n"
    "						The dollar signs in the encrypted form must be escaped.\n"
    " --web-admin					Enable Turn Web-admin support. By default it is disabled.\n"
    " --web-admin-ip=<IP>				Local system IP address to be used for Web-admin server "
    "endpoint. Default value\n"
    "						is 127.0.0.1.\n"
    " --web-admin-port=<port>			Web-admin server port. Default is 8080.\n"
    " --web-admin-listen-on-workers			Enable for web-admin server to listens on STUN/TURN workers "
    "STUN/TURN ports.\n"
    "						By default it is disabled for security reasons!\n"
    "						(This behavior used to be the default behavior, and was enabled by "
    "default.)\n"
    " --server-relay					Server relay. NON-STANDARD AND DANGEROUS OPTION. Only for "
    "those applications\n"
    "						when we want to run server applications on the relay endpoints.\n"
    "						This option eliminates the IP permissions check on the packets\n"
    "						incoming to the relay endpoints.\n"
    " --cli-max-output-sessions			Maximum number of output sessions in ps CLI command.\n"
    "						This value can be changed on-the-fly in CLI. The default value is "
    "256.\n"
    " --ne=[1|2|3]					Set network engine type for the process (for internal "
    "purposes).\n"
    " --no-rfc5780					Disable RFC5780 (NAT behavior discovery).\n"
    "						Originally, if there are more than one listener address from the same\n"
    "						address family, then by default the NAT behavior discovery feature "
    "enabled.\n"
    "						This option disables this original behavior, because the NAT behavior "
    "discovery\n"
    "						adds attributes to response, and this increase the possibility of an "
    "amplification attack.\n"
    "						Strongly encouraged to use this option to decrease gain factor in STUN "
    "binding responses.\n"
    " --no-stun-backward-compatibility		Disable handling old STUN Binding requests and disable MAPPED-ADDRESS "
    "attribute\n"
    "						in binding response (use only the XOR-MAPPED-ADDRESS).\n"
    " --response-origin-only-with-rfc5780		Only send RESPONSE-ORIGIN attribute in binding response if "
    "RFC5780 is enabled.\n"
    " --version					Print version (and exit).\n"
    " -h						Help\n"
    "\n";

static char AdminUsage[] =
    "Usage: turnadmin [command] [options]\n"
    "\nCommands:\n\n"
    "	-P, --generate-encrypted-password	Generate and print to the standard\n"
    "					output an encrypted form of a password\n"
    "					(for web admin user or CLI). See wiki, README or man\n"
    "					pages for more detailed description.\n"
    "	-k, --key			generate long-term credential mechanism key for a user\n"
    "	-a, --add			add/update a long-term mechanism user\n"
    "	-A, --add-admin			add/update a web admin user\n"
    "	-d, --delete			delete a long-term mechanism user\n"
    "	-D, --delete-admin		delete an admin user\n"
    "	-l, --list			list all long-term mechanism users\n"
    "	-L, --list-admin		list all admin users\n"
    "	-s, --set-secret=<value>	Add shared secret for TURN REST API\n"
    "	-S, --show-secret		Show stored shared secrets for TURN REST API\n"
    "	-X, --delete-secret=<value>	Delete a shared secret\n"
    "	    --delete-all-secrets	Delete all shared secrets for REST API\n"
    "	-O, --add-origin		Add origin-to-realm relation.\n"
    "	-R, --del-origin		Delete origin-to-realm relation.\n"
    "	-I, --list-origins		List origin-to-realm relations.\n"
    "	-g, --set-realm-option		Set realm params: max-bps, total-quota, user-quota.\n"
    "	-G, --list-realm-options	List realm params.\n"
    "	-E, --generate-encrypted-password-aes	Generate and print to the standard\n"
    "					output an encrypted form of password with AES-128\n"
    "\nOptions with mandatory values:\n\n"
#if !defined(TURN_NO_SQLITE)
    "	-b, --db, --userdb		SQLite database file, default value is /var/db/turndb or\n"
    "					  /usr/local/var/db/turndb or /var/lib/turn/turndb.\n"
#endif
#if !defined(TURN_NO_PQ)
    "	-e, --psql-userdb, --sql-userdb	PostgreSQL user database connection string, if PostgreSQL DB is used.\n"
#endif
#if !defined(TURN_NO_MYSQL)
    "	-M, --mysql-userdb		MySQL user database connection string, if MySQL DB is used.\n"
#endif
#if !defined(TURN_NO_MONGO)
    "	-J, --mongo-userdb		MongoDB user database connection string, if MongoDB is used.\n"
#endif
#if !defined(TURN_NO_HIREDIS)
    "	-N, --redis-userdb		Redis user database connection string, if Redis DB is used.\n"
#endif
    "	-u, --user			Username\n"
    "	-r, --realm			Realm\n"
    "	-p, --password			Password\n"
    "	-x, --key-path			Generates a 128 bit key into the given path.\n"
    "	-f, --file-key-path		Contains a 128 bit key in the given path.\n"
    "	-v, --verify			Verify a given base64 encrypted type password.\n"
#if !defined(TURN_NO_SQLITE) || !defined(TURN_NO_PQ) || !defined(TURN_NO_MYSQL) || !defined(TURN_NO_MONGO) ||          \
    !defined(TURN_NO_HIREDIS)
    "	-o, --origin			Origin\n"
#endif
    "	--max-bps			Set value of realm's max-bps parameter.\n"
    "					Setting to zero value means removal of the option.\n"
    "	--total-quota			Set value of realm's total-quota parameter.\n"
    "					Setting to zero value means removal of the option.\n"
    "	--user-quota			Set value of realm's user-quota parameter.\n"
    "					Setting to zero value means removal of the option.\n"
    "	-h, --help			Help\n";

#define OPTIONS "c:d:p:L:E:X:i:m:l:r:u:b:B:e:M:J:N:O:q:Q:s:C:K:A:vVofhznaS"

#define ADMIN_OPTIONS "PEgGORIHKYlLkaADSdb:e:M:J:N:u:r:p:s:X:o:h:x:v:f:"

enum EXTRA_OPTS {
  NO_UDP_OPT = 256,
  NO_TCP_OPT,
  TCP_PROXY_PORT_OPT,
  NO_TLS_OPT,
  NO_DTLS_OPT,
  NO_UDP_RELAY_OPT,
  NO_TCP_RELAY_OPT,
  TLS_PORT_OPT,
  ALT_PORT_OPT,
  ALT_TLS_PORT_OPT,
  CERT_FILE_OPT,
  PKEY_FILE_OPT,
  PKEY_PWD_OPT,
  MIN_PORT_OPT,
  MAX_PORT_OPT,
  STALE_NONCE_OPT,
  MAX_ALLOCATE_LIFETIME_OPT,
  CHANNEL_LIFETIME_OPT,
  PERMISSION_LIFETIME_OPT,
  PROMETHEUS_OPT,
  PROMETHEUS_PORT_OPT,
  PROMETHEUS_ENABLE_USERNAMES_OPT,
  AUTH_SECRET_OPT,
  NO_AUTH_PINGS_OPT,
  NO_DYNAMIC_IP_LIST_OPT,
  NO_DYNAMIC_REALMS_OPT,
  DEL_ALL_AUTH_SECRETS_OPT,
  STATIC_AUTH_SECRET_VAL_OPT,
  AUTH_SECRET_TS_EXP, /* deprecated */
  NO_STDOUT_LOG_OPT,
  SYSLOG_OPT,
  SYSLOG_FACILITY_OPT,
  SIMPLE_LOG_OPT,
  NEW_LOG_TIMESTAMP_OPT,
  NEW_LOG_TIMESTAMP_FORMAT_OPT,
  AUX_SERVER_OPT,
  UDP_SELF_BALANCE_OPT,
  ALTERNATE_SERVER_OPT,
  TLS_ALTERNATE_SERVER_OPT,
  NO_MULTICAST_PEERS_OPT,
  ALLOW_LOOPBACK_PEERS_OPT,
  MAX_ALLOCATE_TIMEOUT_OPT,
  ALLOWED_PEER_IPS,
  DENIED_PEER_IPS,
  CIPHER_LIST_OPT,
  PIDFILE_OPT,
  SECURE_STUN_OPT,
  CA_FILE_OPT,
  DH_FILE_OPT,
  NO_STUN_OPT,
  PROC_USER_OPT,
  PROC_GROUP_OPT,
  MOBILITY_OPT,
  NO_CLI_OPT,
  CLI_IP_OPT,
  CLI_PORT_OPT,
  CLI_PASSWORD_OPT,
  WEB_ADMIN_OPT,
  WEB_ADMIN_IP_OPT,
  WEB_ADMIN_PORT_OPT,
  WEB_ADMIN_LISTEN_ON_WORKERS_OPT,
  SERVER_RELAY_OPT,
  CLI_MAX_SESSIONS_OPT,
  EC_CURVE_NAME_OPT,
  DH566_OPT,
  DH1066_OPT,
  NE_TYPE_OPT,
  NO_SSLV2_OPT, /*deprecated*/
  NO_SSLV3_OPT, /*deprecated*/
  NO_TLSV1_OPT,
  NO_TLSV1_1_OPT,
  NO_TLSV1_2_OPT,
  CHECK_ORIGIN_CONSISTENCY_OPT,
  ADMIN_MAX_BPS_OPT,
  ADMIN_TOTAL_QUOTA_OPT,
  ADMIN_USER_QUOTA_OPT,
  SERVER_NAME_OPT,
  OAUTH_OPT,
  NO_SOFTWARE_ATTRIBUTE_OPT,
  NO_HTTP_OPT,
  SECRET_KEY_OPT,
  ACME_REDIRECT_OPT,
  LOG_BINDING_OPT,
  NO_RFC5780,
  NO_STUN_BACKWARD_COMPATIBILITY_OPT,
  RESPONSE_ORIGIN_ONLY_WITH_RFC5780_OPT,
  VERSION_OPT
};

struct myoption {
  const char *name; /* name of long option */
  int has_arg;      /* whether option takes an argument */
  int *flag;        /* if not NULL, set *flag to val when option found */
  int val;          /* if flag is not NULL, value to set *flag to. */
                    /* if flag is NULL, return value */
};

struct uoptions {
  union {
    const struct myoption *m;
    const struct option *o;
  } u;
};

static const struct myoption long_options[] = {
    {"listening-device", required_argument, NULL, 'd'},
    {"listening-port", required_argument, NULL, 'p'},
    {"tls-listening-port", required_argument, NULL, TLS_PORT_OPT},
    {"alt-listening-port", required_argument, NULL, ALT_PORT_OPT},
    {"alt-tls-listening-port", required_argument, NULL, ALT_TLS_PORT_OPT},
    {"tcp-proxy-port", required_argument, NULL, TCP_PROXY_PORT_OPT},
    {"listening-ip", required_argument, NULL, 'L'},
    {"relay-device", required_argument, NULL, 'i'},
    {"relay-ip", required_argument, NULL, 'E'},
    {"external-ip", required_argument, NULL, 'X'},
    {"relay-threads", required_argument, NULL, 'm'},
    {"min-port", required_argument, NULL, MIN_PORT_OPT},
    {"max-port", required_argument, NULL, MAX_PORT_OPT},
    {"lt-cred-mech", optional_argument, NULL, 'a'},
    {"no-auth", optional_argument, NULL, 'z'},
    {"user", required_argument, NULL, 'u'},
    {"userdb", required_argument, NULL, 'b'},
    {"db", required_argument, NULL, 'b'},
#if !defined(TURN_NO_PQ)
    {"psql-userdb", required_argument, NULL, 'e'},
    {"sql-userdb", required_argument, NULL, 'e'},
#endif
#if !defined(TURN_NO_MYSQL)
    {"mysql-userdb", required_argument, NULL, 'M'},
#endif
#if !defined(TURN_NO_MONGO)
    {"mongo-userdb", required_argument, NULL, 'J'},
#endif
#if !defined(TURN_NO_HIREDIS)
    {"redis-userdb", required_argument, NULL, 'N'},
    {"redis-statsdb", required_argument, NULL, 'O'},
#endif
#if !defined(TURN_NO_PROMETHEUS)
    {"prometheus", optional_argument, NULL, PROMETHEUS_OPT},
    {"prometheus-port", optional_argument, NULL, PROMETHEUS_PORT_OPT},
    {"prometheus-username-labels", optional_argument, NULL, PROMETHEUS_ENABLE_USERNAMES_OPT},
#endif
    {"use-auth-secret", optional_argument, NULL, AUTH_SECRET_OPT},
    {"static-auth-secret", required_argument, NULL, STATIC_AUTH_SECRET_VAL_OPT},
    {"no-auth-pings", optional_argument, NULL, NO_AUTH_PINGS_OPT},
    {"no-dynamic-ip-list", optional_argument, NULL, NO_DYNAMIC_IP_LIST_OPT},
    {"no-dynamic-realms", optional_argument, NULL, NO_DYNAMIC_REALMS_OPT},
    /* deprecated: */ {"secret-ts-exp-time", optional_argument, NULL, AUTH_SECRET_TS_EXP},
    {"realm", required_argument, NULL, 'r'},
    {"server-name", required_argument, NULL, SERVER_NAME_OPT},
    {"oauth", optional_argument, NULL, OAUTH_OPT},
    {"user-quota", required_argument, NULL, 'q'},
    {"total-quota", required_argument, NULL, 'Q'},
    {"max-bps", required_argument, NULL, 's'},
    {"bps-capacity", required_argument, NULL, 'B'},
    {"verbose", optional_argument, NULL, 'v'},
    {"Verbose", optional_argument, NULL, 'V'},
    {"daemon", optional_argument, NULL, 'o'},
    /* deprecated: */ {"prod", optional_argument, NULL, NO_SOFTWARE_ATTRIBUTE_OPT},
    {"no-software-attribute", optional_argument, NULL, NO_SOFTWARE_ATTRIBUTE_OPT},
    {"fingerprint", optional_argument, NULL, 'f'},
    {"check-origin-consistency", optional_argument, NULL, CHECK_ORIGIN_CONSISTENCY_OPT},
    {"no-udp", optional_argument, NULL, NO_UDP_OPT},
    {"no-tcp", optional_argument, NULL, NO_TCP_OPT},
    {"no-tls", optional_argument, NULL, NO_TLS_OPT},
    {"no-dtls", optional_argument, NULL, NO_DTLS_OPT},
    {"no-udp-relay", optional_argument, NULL, NO_UDP_RELAY_OPT},
    {"no-tcp-relay", optional_argument, NULL, NO_TCP_RELAY_OPT},
    {"stale-nonce", optional_argument, NULL, STALE_NONCE_OPT},
    {"max-allocate-lifetime", optional_argument, NULL, MAX_ALLOCATE_LIFETIME_OPT},
    {"channel-lifetime", optional_argument, NULL, CHANNEL_LIFETIME_OPT},
    {"permission-lifetime", optional_argument, NULL, PERMISSION_LIFETIME_OPT},
    {"stun-only", optional_argument, NULL, 'S'},
    {"no-stun", optional_argument, NULL, NO_STUN_OPT},
    {"cert", required_argument, NULL, CERT_FILE_OPT},
    {"pkey", required_argument, NULL, PKEY_FILE_OPT},
    {"pkey-pwd", required_argument, NULL, PKEY_PWD_OPT},
    {"log-file", required_argument, NULL, 'l'},
    {"no-stdout-log", optional_argument, NULL, NO_STDOUT_LOG_OPT},
    {"syslog", optional_argument, NULL, SYSLOG_OPT},
    {"simple-log", optional_argument, NULL, SIMPLE_LOG_OPT},
    {"new-log-timestamp", optional_argument, NULL, NEW_LOG_TIMESTAMP_OPT},
    {"new-log-timestamp-format", required_argument, NULL, NEW_LOG_TIMESTAMP_FORMAT_OPT},
    {"aux-server", required_argument, NULL, AUX_SERVER_OPT},
    {"udp-self-balance", optional_argument, NULL, UDP_SELF_BALANCE_OPT},
    {"alternate-server", required_argument, NULL, ALTERNATE_SERVER_OPT},
    {"tls-alternate-server", required_argument, NULL, TLS_ALTERNATE_SERVER_OPT},
    {"rest-api-separator", required_argument, NULL, 'C'},
    {"max-allocate-timeout", required_argument, NULL, MAX_ALLOCATE_TIMEOUT_OPT},
    {"no-multicast-peers", optional_argument, NULL, NO_MULTICAST_PEERS_OPT},
    {"allow-loopback-peers", optional_argument, NULL, ALLOW_LOOPBACK_PEERS_OPT},
    {"allowed-peer-ip", required_argument, NULL, ALLOWED_PEER_IPS},
    {"denied-peer-ip", required_argument, NULL, DENIED_PEER_IPS},
    {"cipher-list", required_argument, NULL, CIPHER_LIST_OPT},
    {"pidfile", required_argument, NULL, PIDFILE_OPT},
    {"secure-stun", optional_argument, NULL, SECURE_STUN_OPT},
    {"CA-file", required_argument, NULL, CA_FILE_OPT},
    {"dh-file", required_argument, NULL, DH_FILE_OPT},
    {"proc-user", required_argument, NULL, PROC_USER_OPT},
    {"proc-group", required_argument, NULL, PROC_GROUP_OPT},
    {"mobility", optional_argument, NULL, MOBILITY_OPT},
    {"no-cli", optional_argument, NULL, NO_CLI_OPT},
    {"cli-ip", required_argument, NULL, CLI_IP_OPT},
    {"cli-port", required_argument, NULL, CLI_PORT_OPT},
    {"cli-password", required_argument, NULL, CLI_PASSWORD_OPT},
    {"web-admin", optional_argument, NULL, WEB_ADMIN_OPT},
    {"web-admin-ip", required_argument, NULL, WEB_ADMIN_IP_OPT},
    {"web-admin-port", required_argument, NULL, WEB_ADMIN_PORT_OPT},
    {"web-admin-listen-on-workers", optional_argument, NULL, WEB_ADMIN_LISTEN_ON_WORKERS_OPT},
    {"server-relay", optional_argument, NULL, SERVER_RELAY_OPT},
    {"cli-max-output-sessions", required_argument, NULL, CLI_MAX_SESSIONS_OPT},
    {"ec-curve-name", required_argument, NULL, EC_CURVE_NAME_OPT},
    {"dh566", optional_argument, NULL, DH566_OPT},
    {"dh1066", optional_argument, NULL, DH1066_OPT},
    {"ne", required_argument, NULL, NE_TYPE_OPT},
    {"no-sslv2", optional_argument, NULL, NO_SSLV2_OPT}, /* deprecated */
    {"no-sslv3", optional_argument, NULL, NO_SSLV3_OPT}, /* deprecated */
    {"no-tlsv1", optional_argument, NULL, NO_TLSV1_OPT},
    {"no-tlsv1_1", optional_argument, NULL, NO_TLSV1_1_OPT},
    {"no-tlsv1_2", optional_argument, NULL, NO_TLSV1_2_OPT},
    {"secret-key-file", required_argument, NULL, SECRET_KEY_OPT},
    {"keep-address-family", optional_argument, NULL, 'K'},
    {"allocation-default-address-family", required_argument, NULL, 'A'},
    {"acme-redirect", required_argument, NULL, ACME_REDIRECT_OPT},
    {"log-binding", optional_argument, NULL, LOG_BINDING_OPT},
    {"no-rfc5780", optional_argument, NULL, NO_RFC5780},
    {"no-stun-backward-compatibility", optional_argument, NULL, NO_STUN_BACKWARD_COMPATIBILITY_OPT},
    {"response-origin-only-with-rfc5780", optional_argument, NULL, RESPONSE_ORIGIN_ONLY_WITH_RFC5780_OPT},
    {"version", optional_argument, NULL, VERSION_OPT},
    {"syslog-facility", required_argument, NULL, SYSLOG_FACILITY_OPT},
    {NULL, no_argument, NULL, 0}};

static const struct myoption admin_long_options[] = {
    {"generate-encrypted-password", no_argument, NULL, 'P'},
    {"generate-encrypted-password-aes", no_argument, NULL, 'E'},
    {"key", no_argument, NULL, 'k'},
    {"add", no_argument, NULL, 'a'},
    {"delete", no_argument, NULL, 'd'},
    {"list", no_argument, NULL, 'l'},
    {"list-admin", no_argument, NULL, 'L'},
    {"set-secret", required_argument, NULL, 's'},
    {"show-secret", no_argument, NULL, 'S'},
    {"delete-secret", required_argument, NULL, 'X'},
    {"delete-all-secrets", no_argument, NULL, DEL_ALL_AUTH_SECRETS_OPT},
    {"add-admin", no_argument, NULL, 'A'},
    {"delete-admin", no_argument, NULL, 'D'},
#if !defined(TURN_NO_SQLITE)
    {"userdb", required_argument, NULL, 'b'},
    {"db", required_argument, NULL, 'b'},
#endif
#if !defined(TURN_NO_PQ)
    {"psql-userdb", required_argument, NULL, 'e'},
    {"sql-userdb", required_argument, NULL, 'e'},
#endif
#if !defined(TURN_NO_MYSQL)
    {"mysql-userdb", required_argument, NULL, 'M'},
#endif
#if !defined(TURN_NO_MONGO)
    {"mongo-userdb", required_argument, NULL, 'J'},
#endif
#if !defined(TURN_NO_HIREDIS)
    {"redis-userdb", required_argument, NULL, 'N'},
#endif
    {"user", required_argument, NULL, 'u'},
    {"realm", required_argument, NULL, 'r'},
    {"password", required_argument, NULL, 'p'},
    {"file-key-path", required_argument, NULL, 'f'},
    {"verify", required_argument, NULL, 'v'},
    {"key-path", required_argument, NULL, 'x'},
    {"add-origin", no_argument, NULL, 'O'},
    {"del-origin", no_argument, NULL, 'R'},
    {"list-origins", required_argument, NULL, 'I'},
    {"origin", required_argument, NULL, 'o'},
    {"set-realm-option", no_argument, NULL, 'g'},
    {"list-realm-option", no_argument, NULL, 'G'},
    {"user-quota", required_argument, NULL, ADMIN_USER_QUOTA_OPT},
    {"total-quota", required_argument, NULL, ADMIN_TOTAL_QUOTA_OPT},
    {"max-bps", required_argument, NULL, ADMIN_MAX_BPS_OPT},
    {"help", no_argument, NULL, 'h'},
    {NULL, no_argument, NULL, 0}};

int init_ctr(struct ctr_state *state, const unsigned char iv[8]) {
  state->num = 0;
  memset(state->ecount, 0, 16);
  memset(state->ivec + 8, 0, 8);
  memcpy(state->ivec, iv, 8);
  return 1;
}

unsigned char *base64encode(const void *b64_encode_this, int encode_this_many_bytes) {
  BIO *b64_bio, *mem_bio;                         // Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
  BUF_MEM *mem_bio_mem_ptr;                       // Pointer to a "memory BIO" structure holding our base64 data.
  b64_bio = BIO_new(BIO_f_base64());              // Initialize our base64 filter BIO.
  mem_bio = BIO_new(BIO_s_mem());                 // Initialize our memory sink BIO.
  BIO_push(b64_bio, mem_bio);                     // Link the BIOs by creating a filter-sink BIO chain.
  BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL); // No newlines every 64 characters or less.
  BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); // Records base64 encoded data.
  (void)BIO_flush(b64_bio);                   // Flush data. Necessary for b64 encoding, because of pad characters.
  BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr); // Store address of mem_bio's memory structure.
  (void)BIO_set_close(mem_bio, BIO_NOCLOSE);  // Permit access to mem_ptr after BIOs are destroyed.
  BIO_free_all(b64_bio);                      // Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
  BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1); // Makes space for end null.
  (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';    // Adds null-terminator to tail.
  return (unsigned char *)(*mem_bio_mem_ptr).data; // Returns base-64 encoded data. (See: "buf_mem_st" struct).
}
void encrypt_aes_128(unsigned char *in, const unsigned char *mykey) {

  int j = 0, k = 0;
  int totalSize = 0;
  AES_KEY key;
  unsigned char iv[8] = {0}; // changed
  unsigned char out[1024];   // changed
  AES_set_encrypt_key(mykey, 128, &key);
  char total[256];
  int size = 0;
  struct ctr_state state;
  init_ctr(&state, iv);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  CRYPTO_ctr128_encrypt(in, out, strlen((char *)in), &key, state.ivec, state.ecount, &state.num,
                        (block128_f)AES_encrypt);
#else
  AES_ctr128_encrypt(in, out, strlen((char *)in), &key, state.ivec, state.ecount, &state.num);
#endif

  totalSize += strlen((char *)in);
  size = strlen((char *)in);
  for (j = 0; j < size; j++) {
    total[k++] = out[j];
  }

  unsigned char *base64_encoded = base64encode(total, totalSize);
  printf("%s\n", base64_encoded);
}
void generate_aes_128_key(char *filePath, unsigned char *returnedKey) {
  int i;
  int part;
  FILE *fptr;
  char key[16];
  struct timespec times;
  clock_gettime(CLOCK_REALTIME, &times);
  srand(times.tv_nsec);

  for (i = 0; i < 16; i++) {
    part = (rand() % 3);
    if (part == 0) {
      key[i] = (rand() % 10) + 48;
    }

    else if (part == 1) {
      key[i] = (rand() % 26) + 65;
    }

    else if (part == 2) {
      key[i] = (rand() % 26) + 97;
    }
  }
  fptr = fopen(filePath, "w");
  for (i = 0; i < 16; i++) {
    fputc(key[i], fptr);
  }
  STRCPY((char *)returnedKey, key);
  fclose(fptr);
}

unsigned char *base64decode(const void *b64_decode_this, int decode_this_many_bytes) {
  BIO *b64_bio, *mem_bio; // Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
  unsigned char *base64_decoded =
      (unsigned char *)calloc((decode_this_many_bytes * 3) / 4 + 1, sizeof(char)); //+1 = null.
  b64_bio = BIO_new(BIO_f_base64());                                               // Initialize our base64 filter BIO.
  mem_bio = BIO_new(BIO_s_mem());                                                  // Initialize our memory source BIO.
  BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes);                     // Base64 data saved in source.
  BIO_push(b64_bio, mem_bio);                     // Link the BIOs by creating a filter-source BIO chain.
  BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL); // Don't require trailing newlines.
  int decoded_byte_index = 0;                     // Index where the next base64_decoded byte should be written.
  while (0 < BIO_read(b64_bio, base64_decoded + decoded_byte_index, 1)) { // Read byte-by-byte.
    decoded_byte_index++; // Increment the index until read of BIO decoded data is complete.
  }                       // Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
  BIO_free_all(b64_bio);  // Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
  return base64_decoded;  // Returns base-64 decoded data with trailing null terminator.
}
int decodedTextSize(char *input) {
  int i = 0;
  int result = 0, padding = 0;
  int size = strlen(input);
  for (i = 0; i < size; ++i) {
    if (input[i] == '=') {
      padding++;
    }
  }
  result = (strlen(input) / 4 * 3) - padding;
  return result;
}
void decrypt_aes_128(char *in, const unsigned char *mykey) {

  unsigned char iv[8] = {0};
  AES_KEY key;
  unsigned char outdata[256];
  AES_set_encrypt_key(mykey, 128, &key);
  int newTotalSize = decodedTextSize(in);
  int bytes_to_decode = strlen(in);
  unsigned char *encryptedText = base64decode(in, bytes_to_decode);
  char last[1024] = "";
  struct ctr_state state;
  init_ctr(&state, iv);
  memset(outdata, '\0', sizeof(outdata));

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  CRYPTO_ctr128_encrypt(encryptedText, outdata, newTotalSize, &key, state.ivec, state.ecount, &state.num,
                        (block128_f)AES_encrypt);
#else
  AES_ctr128_encrypt(encryptedText, outdata, newTotalSize, &key, state.ivec, state.ecount, &state.num);
#endif

  strcat(last, (char *)outdata);
  printf("%s\n", last);
}

static int get_int_value(const char *s, int default_value) {
  if (!s || !(s[0]))
    return default_value;
  return atoi(s);
}

static int get_bool_value(const char *s) {
  if (!s || !(s[0]))
    return 1;
  if (s[0] == '0' || s[0] == 'n' || s[0] == 'N' || s[0] == 'f' || s[0] == 'F')
    return 0;
  if (s[0] == 'y' || s[0] == 'Y' || s[0] == 't' || s[0] == 'T')
    return 1;
  if (s[0] > '0' && s[0] <= '9')
    return 1;
  if (!strcmp(s, "off") || !strcmp(s, "OFF") || !strcmp(s, "Off"))
    return 0;
  if (!strcmp(s, "on") || !strcmp(s, "ON") || !strcmp(s, "On"))
    return 1;
  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown boolean value: %s. You can use on/off, yes/no, 1/0, true/false.\n", s);
  exit(-1);
}

static void set_option(int c, char *value) {
  if (value && value[0] == '=') {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                  "WARNING: option -%c is possibly used incorrectly. The short form of the option must be used as "
                  "this: -%c <value>, no \'equals\' sign may be used, that sign is used only with long form options "
                  "(like --user=<username>).\n",
                  (char)c, (char)c);
  }

  switch (c) {
  case 'K':
    if (get_bool_value(value))
      turn_params.allocation_default_address_family = ALLOCATION_DEFAULT_ADDRESS_FAMILY_KEEP;
    break;
  case 'A':
    if (value && strlen(value) > 0) {
      if (*value == '=')
        ++value;
      if (!strcmp(value, "ipv6")) {
        turn_params.allocation_default_address_family = ALLOCATION_DEFAULT_ADDRESS_FAMILY_IPV6;
      } else if (!strcmp(value, "keep")) {
        turn_params.allocation_default_address_family = ALLOCATION_DEFAULT_ADDRESS_FAMILY_KEEP;
      } else if (!strcmp(value, "ipv4")) {
        turn_params.allocation_default_address_family = ALLOCATION_DEFAULT_ADDRESS_FAMILY_IPV4;
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "ERROR: invalid allocation_default_address_family parameter\n");
      }
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "ERROR: invalid allocation_default_address_family parameter\n");
    }
    break;
  case SERVER_NAME_OPT:
    STRCPY(turn_params.oauth_server_name, value);
    break;
  case OAUTH_OPT:
    if (ENC_ALG_NUM == 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: option --oauth is not supported; ignored.\n");
    } else {
      turn_params.oauth = get_bool_value(value);
    }
    break;
  case NO_SSLV2_OPT:
    // deprecated
    break;
  case NO_SSLV3_OPT:
    // deprecated
    break;
  case NO_TLSV1_OPT:
    turn_params.no_tlsv1 = get_bool_value(value);
    break;
  case NO_TLSV1_1_OPT:
    turn_params.no_tlsv1_1 = get_bool_value(value);
    break;
  case NO_TLSV1_2_OPT:
    turn_params.no_tlsv1_2 = get_bool_value(value);
    break;
  case NE_TYPE_OPT: {
    int ne = atoi(value);
    if ((ne < (int)NEV_MIN) || (ne > (int)NEV_MAX)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "ERROR: wrong version of the network engine: %d\n", ne);
    }
    turn_params.net_engine_version = (NET_ENG_VERSION)ne;
  } break;
  case DH566_OPT:
    if (get_bool_value(value))
      turn_params.dh_key_size = DH_566;
    break;
  case DH1066_OPT:
    if (get_bool_value(value))
      turn_params.dh_key_size = DH_1066;
    break;
  case EC_CURVE_NAME_OPT:
    STRCPY(turn_params.ec_curve_name, value);
    break;
  case CLI_MAX_SESSIONS_OPT:
    cli_max_output_sessions = atoi(value);
    break;
  case SERVER_RELAY_OPT:
    turn_params.server_relay = get_bool_value(value);
    break;
  case MOBILITY_OPT:
    turn_params.mobility = get_bool_value(value);
    break;
  case NO_CLI_OPT:
    use_cli = !get_bool_value(value);
    break;
  case CLI_IP_OPT:
    if (make_ioa_addr((const uint8_t *)value, 0, &cli_addr) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot set cli address: %s\n", value);
    } else {
      cli_addr_set = 1;
    }
    break;
  case CLI_PORT_OPT:
    cli_port = atoi(value);
    break;
  case CLI_PASSWORD_OPT:
    STRCPY(cli_password, value);
    break;
  case WEB_ADMIN_OPT:
    use_web_admin = get_bool_value(value);
    break;
  case WEB_ADMIN_IP_OPT:
    if (make_ioa_addr((const uint8_t *)value, 0, &web_admin_addr) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot set web-admin address: %s\n", value);
    } else {
      web_admin_addr_set = 1;
    }
    break;
  case WEB_ADMIN_PORT_OPT:
    web_admin_port = atoi(value);
    break;
  case WEB_ADMIN_LISTEN_ON_WORKERS_OPT:
    turn_params.web_admin_listen_on_workers = get_bool_value(value);
    break;
#if defined(WINDOWS)
    // TODO: implement it!!!
#else
  case PROC_USER_OPT: {
    struct passwd *pwd = getpwnam(value);
    if (!pwd) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown user name: %s\n", value);
      exit(-1);
    } else {
      procuserid = pwd->pw_uid;
      procuserid_set = 1;
      STRCPY(procusername, value);
    }
  } break;
  case PROC_GROUP_OPT: {
    struct group *gr = getgrnam(value);
    if (!gr) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown group name: %s\n", value);
      exit(-1);
    } else {
      procgroupid = gr->gr_gid;
      procgroupid_set = 1;
      STRCPY(procgroupname, value);
    }
  } break;
#endif
  case 'i':
    STRCPY(turn_params.relay_ifname, value);
    break;
  case 'm':
    if (atoi(value) > MAX_NUMBER_OF_GENERAL_RELAY_SERVERS) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: max number of relay threads is 128.\n");
      turn_params.general_relay_servers_number = MAX_NUMBER_OF_GENERAL_RELAY_SERVERS;
    } else if (atoi(value) <= 0) {
      turn_params.general_relay_servers_number = 0;
    } else {
      turn_params.general_relay_servers_number = atoi(value);
    }
    break;
  case 'd':
    STRCPY(turn_params.listener_ifname, value);
    break;
  case 'p':
    turn_params.listener_port = atoi(value);
    break;
  case TLS_PORT_OPT:
    turn_params.tls_listener_port = atoi(value);
    break;
  case ALT_PORT_OPT:
    turn_params.alt_listener_port = atoi(value);
    break;
  case ALT_TLS_PORT_OPT:
    turn_params.alt_tls_listener_port = atoi(value);
    break;
  case TCP_PROXY_PORT_OPT:
    turn_params.tcp_proxy_port = atoi(value);
    turn_params.tcp_use_proxy = 1;
    break;
  case MIN_PORT_OPT:
    turn_params.min_port = atoi(value);
    break;
  case MAX_PORT_OPT:
    turn_params.max_port = atoi(value);
    break;
  case SECURE_STUN_OPT:
    turn_params.secure_stun = get_bool_value(value);
    break;
  case NO_MULTICAST_PEERS_OPT:
    turn_params.no_multicast_peers = get_bool_value(value);
    break;
  case ALLOW_LOOPBACK_PEERS_OPT:
    turn_params.allow_loopback_peers = get_bool_value(value);
    break;
  case STALE_NONCE_OPT:
    turn_params.stale_nonce = get_int_value(value, STUN_DEFAULT_NONCE_EXPIRATION_TIME);
    break;
  case MAX_ALLOCATE_LIFETIME_OPT:
    turn_params.max_allocate_lifetime = get_int_value(value, STUN_DEFAULT_MAX_ALLOCATE_LIFETIME);
    break;
  case CHANNEL_LIFETIME_OPT:
    turn_params.channel_lifetime = get_int_value(value, STUN_DEFAULT_CHANNEL_LIFETIME);
    break;
  case PERMISSION_LIFETIME_OPT:
    turn_params.permission_lifetime = get_int_value(value, STUN_DEFAULT_PERMISSION_LIFETIME);
    break;
  case MAX_ALLOCATE_TIMEOUT_OPT:
    TURN_MAX_ALLOCATE_TIMEOUT = atoi(value);
    TURN_MAX_ALLOCATE_TIMEOUT_STUN_ONLY = atoi(value);
    break;
  case 'S':
    turn_params.stun_only = get_bool_value(value);
    break;
  case NO_STUN_OPT:
    turn_params.no_stun = get_bool_value(value);
    break;
  case 'L':
    add_listener_addr(value);
    break;
  case 'E':
    add_relay_addr(value);
    break;
  case 'X':
    if (value) {
      char *div = strchr(value, '/');
      if (div) {
        char *nval = strdup(value);
        div = strchr(nval, '/');
        div[0] = 0;
        ++div;
        ioa_addr apub, apriv;
        if (make_ioa_addr((const uint8_t *)nval, 0, &apub) < 0) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "-X : Wrong address format: %s\n", nval);
        } else {
          if (make_ioa_addr((const uint8_t *)div, 0, &apriv) < 0) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "-X : Wrong address format: %s\n", div);
          } else {
            ioa_addr_add_mapping(&apub, &apriv);
            if (add_ip_list_range((const char *)div, NULL, &turn_params.ip_whitelist) == 0)
              TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Whitelisting external-ip private part: %s\n", div);
          }
        }
        free(nval);
      } else {
        if (turn_params.external_ip) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "You cannot define external IP more than once in the configuration\n");
        } else {
          turn_params.external_ip =
              (ioa_addr *)allocate_super_memory_engine(turn_params.listener.ioa_eng, sizeof(ioa_addr));
          if (make_ioa_addr((const uint8_t *)value, 0, turn_params.external_ip) < 0) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "-X : Wrong address format: %s\n", value);
            free(turn_params.external_ip);
            turn_params.external_ip = NULL;
          }
        }
      }
    }
    break;
  case 'v':
    if (turn_params.verbose != TURN_VERBOSE_EXTRA) {
      if (get_bool_value(value)) {
        turn_params.verbose = TURN_VERBOSE_NORMAL;
      } else {
        turn_params.verbose = TURN_VERBOSE_NONE;
      }
    }
    break;
  case 'V':
    if (get_bool_value(value)) {
      turn_params.verbose = TURN_VERBOSE_EXTRA;
    }
    break;
  case 'o':
    turn_params.turn_daemon = get_bool_value(value);
    break;
  case 'a':
    if (get_bool_value(value)) {
      turn_params.ct = TURN_CREDENTIALS_LONG_TERM;
      use_lt_credentials = 1;
      use_ltc = 1;
    } else {
      turn_params.ct = TURN_CREDENTIALS_UNDEFINED;
      use_lt_credentials = 0;
    }
    break;
  case 'z':
    if (!get_bool_value(value)) {
      turn_params.ct = TURN_CREDENTIALS_UNDEFINED;
      anon_credentials = 0;
    } else {
      turn_params.ct = TURN_CREDENTIALS_NONE;
      anon_credentials = 1;
    }
    break;
  case NO_SOFTWARE_ATTRIBUTE_OPT:
    turn_params.no_software_attribute = get_bool_value(value);
    break;
  case 'f':
    turn_params.fingerprint = get_bool_value(value);
    break;
  case 'u':
    add_static_user_account(value);
    break;
  case 'b': {
#if defined(TURN_NO_SQLITE)
    TURN_LOG_FUNC(
        TURN_LOG_LEVEL_WARNING,
        "WARNING: Options -b, --userdb and --db are not supported because SQLite is not supported in this build.\n");
#else
    STRCPY(turn_params.default_users_db.persistent_users_db.userdb, value);
    turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_SQLITE;
#endif
  } break;
#if !defined(TURN_NO_PQ)
  case 'e':
    STRCPY(turn_params.default_users_db.persistent_users_db.userdb, value);
    turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_PQ;
    break;
#endif
#if !defined(TURN_NO_MYSQL)
  case 'M':
    STRCPY(turn_params.default_users_db.persistent_users_db.userdb, value);
    turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_MYSQL;
    break;
#endif
#if !defined(TURN_NO_MONGO)
  case 'J':
    STRCPY(turn_params.default_users_db.persistent_users_db.userdb, value);
    turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_MONGO;
    break;
#endif
#if !defined(TURN_NO_HIREDIS)
  case 'N':
    STRCPY(turn_params.default_users_db.persistent_users_db.userdb, value);
    turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_REDIS;
    break;
  case 'O':
    STRCPY(turn_params.redis_statsdb.connection_string, value);
    turn_params.use_redis_statsdb = 1;
    break;
#endif
  case PROMETHEUS_OPT:
    turn_params.prometheus = 1;
    break;
  case PROMETHEUS_PORT_OPT:
    turn_params.prometheus_port = atoi(value);
    break;
  case PROMETHEUS_ENABLE_USERNAMES_OPT:
    turn_params.prometheus_username_labels = 1;
    break;
  case AUTH_SECRET_OPT:
    turn_params.use_auth_secret_with_timestamp = 1;
    use_tltc = 1;
    turn_params.ct = TURN_CREDENTIALS_LONG_TERM;
    use_lt_credentials = 1;
    break;
  case NO_AUTH_PINGS_OPT:
    turn_params.no_auth_pings = 1;
    break;
  case NO_DYNAMIC_IP_LIST_OPT:
    turn_params.no_dynamic_ip_list = 1;
    break;
  case NO_DYNAMIC_REALMS_OPT:
    turn_params.no_dynamic_realms = 1;
    break;
  case STATIC_AUTH_SECRET_VAL_OPT:
    add_to_secrets_list(&turn_params.default_users_db.ram_db.static_auth_secrets, value);
    turn_params.use_auth_secret_with_timestamp = 1;
    use_tltc = 1;
    turn_params.ct = TURN_CREDENTIALS_LONG_TERM;
    use_lt_credentials = 1;
    break;
  case AUTH_SECRET_TS_EXP:
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: Option --secret-ts-exp-time deprecated and has no effect.\n");
    break;
  case 'r':
    set_default_realm_name(value);
    break;
  case 'q':
    turn_params.user_quota = (vint)atoi(value);
    get_realm(NULL)->options.perf_options.user_quota = atoi(value);
    break;
  case 'Q':
    turn_params.total_quota = (vint)atoi(value);
    get_realm(NULL)->options.perf_options.total_quota = atoi(value);
    break;
  case 's':
    turn_params.max_bps = (band_limit_t)strtoul(value, NULL, 10);
    get_realm(NULL)->options.perf_options.max_bps = (band_limit_t)strtoul(value, NULL, 10);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%lu bytes per second allowed per session\n",
                  (unsigned long)turn_params.max_bps);
    break;
  case 'B':
    turn_params.bps_capacity = (band_limit_t)strtoul(value, NULL, 10);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%lu bytes per second allowed, combined server capacity\n",
                  (unsigned long)turn_params.bps_capacity);
    break;
  case CHECK_ORIGIN_CONSISTENCY_OPT:
    turn_params.check_origin = get_bool_value(value);
    break;
  case NO_UDP_OPT:
    turn_params.no_udp = get_bool_value(value);
    break;
  case NO_TCP_OPT:
    turn_params.no_tcp = get_bool_value(value);
    break;
  case NO_UDP_RELAY_OPT:
    turn_params.no_udp_relay = get_bool_value(value);
    break;
  case NO_TCP_RELAY_OPT:
    turn_params.no_tcp_relay = get_bool_value(value);
    break;
  case NO_TLS_OPT:
#if !TLS_SUPPORTED
    turn_params.no_tls = 1;
#else
    turn_params.no_tls = get_bool_value(value);
#endif
    break;
  case NO_DTLS_OPT:
#if DTLS_SUPPORTED
    turn_params.no_dtls = get_bool_value(value);
#else
    turn_params.no_dtls = 1;
#endif
    break;
  case CERT_FILE_OPT:
    STRCPY(turn_params.cert_file, value);
    break;
  case CA_FILE_OPT:
    STRCPY(turn_params.ca_cert_file, value);
    break;
  case DH_FILE_OPT:
    STRCPY(turn_params.dh_file, value);
    break;
  case SECRET_KEY_OPT:
    STRCPY(turn_params.secret_key_file, value);
    break;
  case PKEY_FILE_OPT:
    STRCPY(turn_params.pkey_file, value);
    break;
  case PKEY_PWD_OPT:
    STRCPY(turn_params.tls_password, value);
    break;
  case ALTERNATE_SERVER_OPT:
    add_alternate_server(value);
    break;
  case AUX_SERVER_OPT:
    add_aux_server(value);
    break;
  case UDP_SELF_BALANCE_OPT:
    turn_params.udp_self_balance = get_bool_value(value);
    break;
  case TLS_ALTERNATE_SERVER_OPT:
    add_tls_alternate_server(value);
    break;
  case ALLOWED_PEER_IPS:
    if (add_ip_list_range(value, NULL, &turn_params.ip_whitelist) == 0)
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "White listing: %s\n", value);
    break;
  case DENIED_PEER_IPS:
    if (add_ip_list_range(value, NULL, &turn_params.ip_blacklist) == 0)
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Black listing: %s\n", value);
    break;
  case CIPHER_LIST_OPT:
    STRCPY(turn_params.cipher_list, value);
    break;
  case PIDFILE_OPT:
    STRCPY(turn_params.pidfile, value);
    break;
  case ACME_REDIRECT_OPT:
    STRCPY(turn_params.acme_redirect, value);
    break;
  case 'C':
    if (value && *value) {
      turn_params.rest_api_separator = *value;
    }
    break;
  case LOG_BINDING_OPT:
    turn_params.log_binding = get_bool_value(value);
    break;
  case NO_RFC5780:
    turn_params.rfc5780 = 0;
    break;
  case NO_STUN_BACKWARD_COMPATIBILITY_OPT:
    turn_params.no_stun_backward_compatibility = get_bool_value(value);
    break;
  case RESPONSE_ORIGIN_ONLY_WITH_RFC5780_OPT:
    turn_params.response_origin_only_with_rfc5780 = get_bool_value(value);
    break;

  /* these options have been already taken care of before: */
  case 'l':
  case NO_STDOUT_LOG_OPT:
  case SYSLOG_OPT:
  case SIMPLE_LOG_OPT:
  case NEW_LOG_TIMESTAMP_OPT:
  case NEW_LOG_TIMESTAMP_FORMAT_OPT:
  case SYSLOG_FACILITY_OPT:
  case 'c':
  case 'n':
  case 'h':
    break;
  default:
    fprintf(stderr, "\n%s\n", Usage);
    exit(-1);
  }

  if (turn_params.default_users_db.persistent_users_db.userdb[0]) {
    char *userdb_sanitized = sanitize_userdb_string(turn_params.default_users_db.persistent_users_db.userdb);
    STRCPY(turn_params.default_users_db.persistent_users_db.userdb_sanitized, userdb_sanitized);
    free(userdb_sanitized);
  }
  if (turn_params.redis_statsdb.connection_string[0]) {
    char *connection_string = sanitize_userdb_string(turn_params.redis_statsdb.connection_string);
    STRCPY(turn_params.redis_statsdb.connection_string_sanitized, connection_string);
    free(connection_string);
  }
}

static int parse_arg_string(char *sarg, int *c, char **value) {
  int i = 0;
  char *name = sarg;
  while (*sarg) {
    if ((*sarg == ' ') || (*sarg == '=') || (*sarg == '\t')) {
      *sarg = 0;
      do {
        ++sarg;
      } while ((*sarg == ' ') || (*sarg == '=') || (*sarg == '\t'));
      *value = sarg;
      break;
    }
    ++sarg;
    *value = sarg;
  }

  if (value && *value && **value == '\"') {
    *value += 1;
    size_t len = strlen(*value);
    while (len > 0 && (((*value)[len - 1] == '\n') || ((*value)[len - 1] == '\r') || ((*value)[len - 1] == ' ') ||
                       ((*value)[len - 1] == '\t'))) {
      (*value)[--len] = 0;
    }
    if (len > 0 && (*value)[len - 1] == '\"') {
      (*value)[--len] = 0;
    }
  }

  while (long_options[i].name) {
    if (strcmp(long_options[i].name, name)) {
      ++i;
      continue;
    }
    *c = long_options[i].val;
    return 0;
  }

  return -1;
}

static void read_config_file(int argc, char **argv, int pass) {
  static char config_file[1025] = DEFAULT_CONFIG_FILE;

  if (pass == 0) {

    if (argv) {
      int i = 0;
      for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-c")) {
          if (i < argc - 1) {
            STRCPY(config_file, argv[i + 1]);
          } else {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Wrong usage of -c option\n");
          }
        } else if (!strcmp(argv[i], "-n")) {
          turn_params.do_not_use_config_file = 1;
          config_file[0] = 0;
          return;
        } else if (!strcmp(argv[i], "-h")) {
          printf("\n%s\n", Usage);
          exit(0);
        } else if (!strcmp(argv[i], "--version")) {
          printf("%s\n", TURN_SERVER_VERSION);
          exit(0);
        }
      }
    }
  }

  if (!turn_params.do_not_use_config_file && config_file[0]) {

    FILE *f = NULL;
    char *full_path_to_config_file = NULL;

    full_path_to_config_file = find_config_file(config_file, pass);
    if (full_path_to_config_file)
      f = fopen(full_path_to_config_file, "r");

    if (f) {

      char sbuf[1025];
      char sarg[1035];

      for (;;) {
        char *s = fgets(sbuf, sizeof(sbuf) - 1, f);
        if (!s)
          break;
        s = skip_blanks(s);
        if (s[0] == '#')
          continue;
        if (!s[0])
          continue;
        size_t slen = strlen(s);

        // strip white-spaces from config file lines end
        while (slen && isspace(s[slen - 1]))
          s[--slen] = 0;
        if (slen) {
          int c = 0;
          char *value = NULL;
          STRCPY(sarg, s);
          if (parse_arg_string(sarg, &c, &value) < 0) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Bad configuration format: %s\n", sarg);
          } else if ((pass == 0) && (c == 'l')) {
            set_logfile(value);
          } else if ((pass == 0) && (c == NO_STDOUT_LOG_OPT)) {
            set_no_stdout_log(get_bool_value(value));
          } else if ((pass == 0) && (c == SYSLOG_OPT)) {
            set_log_to_syslog(get_bool_value(value));
          } else if ((pass == 0) && (c == SIMPLE_LOG_OPT)) {
            set_simple_log(get_bool_value(value));
          } else if ((pass == 0) && (c == NEW_LOG_TIMESTAMP_OPT)) {
            use_new_log_timestamp_format = 1;
          } else if ((pass == 0) && (c == NEW_LOG_TIMESTAMP_FORMAT_OPT)) {
            set_turn_log_timestamp_format(value);
          } else if ((pass == 0) && (c == SYSLOG_FACILITY_OPT)) {
            set_syslog_facility(value);
          } else if ((pass == 1) && (c != 'u')) {
            set_option(c, value);
          } else if ((pass == 2) && (c == 'u')) {
            set_option(c, value);
          }
          if (s[slen - 1] == 59) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Check config! The following line ends with semicolon: \"%s\" \n", s);
          }
        }
      }

      fclose(f);

    } else if (pass == 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                    "Cannot find config file: %s. Default and command-line settings will be used.\n", config_file);
    }

    if (full_path_to_config_file) {
      free(full_path_to_config_file);
      full_path_to_config_file = NULL;
    }
  }
}

static int disconnect_database(void) {
  const turn_dbdriver_t *dbd = get_dbdriver();
  if (dbd && dbd->disconnect) {
    dbd->disconnect();
  }
  return 0;
}

static int adminmain(int argc, char **argv) {
  int c = 0;
  int rc = 0;

  TURNADMIN_COMMAND_TYPE ct = TA_COMMAND_UNKNOWN;

  int is_admin = 0;
  FILE *fptr;
  unsigned char generated_key[16]; // changed

  uint8_t user[STUN_MAX_USERNAME_SIZE + 1] = "\0";
  uint8_t realm[STUN_MAX_REALM_SIZE + 1] = "\0";
  uint8_t pwd[STUN_MAX_PWD_SIZE + 1] = "\0";
  uint8_t secret[AUTH_SECRET_SIZE + 1] = "\0";
  uint8_t origin[STUN_MAX_ORIGIN_SIZE + 1] = "\0";
  perf_options_t po = {(band_limit_t)-1, -1, -1};

  struct uoptions uo;
  uo.u.m = admin_long_options;

  int print_enc_password = 0;
  int print_enc_aes_password = 0;

  while (((c = getopt_long(argc, argv, ADMIN_OPTIONS, uo.u.o, NULL)) != -1)) {
    switch (c) {
    case 'P':
      if (pwd[0]) {
        char result[257];
        generate_new_enc_password((char *)pwd, result);
        printf("%s\n", result);
        exit(0);
      }
      print_enc_password = 1;
      break;
    case 'E':
      print_enc_aes_password = 1;
      break;
    case 'g':
      ct = TA_SET_REALM_OPTION;
      break;
    case 'G':
      ct = TA_LIST_REALM_OPTIONS;
      break;
    case ADMIN_USER_QUOTA_OPT:
      po.user_quota = (vint)atoi(optarg);
      break;
    case ADMIN_TOTAL_QUOTA_OPT:
      po.total_quota = (vint)atoi(optarg);
      break;
    case ADMIN_MAX_BPS_OPT:
      po.max_bps = (vint)atoi(optarg);
      break;
    case 'O':
      ct = TA_ADD_ORIGIN;
      break;
    case 'R':
      ct = TA_DEL_ORIGIN;
      break;
    case 'I':
      ct = TA_LIST_ORIGINS;
      break;
    case 'o':
      STRCPY(origin, optarg);
      break;
    case 'k':
      ct = TA_PRINT_KEY;
      break;
    case 'a':
      ct = TA_UPDATE_USER;
      break;
    case 'd':
      ct = TA_DELETE_USER;
      break;
    case 'A':
      ct = TA_UPDATE_USER;
      is_admin = 1;
      break;
    case 'D':
      ct = TA_DELETE_USER;
      is_admin = 1;
      break;
    case 'l':
      ct = TA_LIST_USERS;
      break;
    case 'L':
      ct = TA_LIST_USERS;
      is_admin = 1;
      break;
    case 's':
      ct = TA_SET_SECRET;
      STRCPY(secret, optarg);
      break;
    case 'S':
      ct = TA_SHOW_SECRET;
      break;
    case 'X':
      ct = TA_DEL_SECRET;
      if (optarg)
        STRCPY(secret, optarg);
      break;
    case DEL_ALL_AUTH_SECRETS_OPT:
      ct = TA_DEL_SECRET;
      break;
#if !defined(TURN_NO_SQLITE)
    case 'b':
      STRCPY(turn_params.default_users_db.persistent_users_db.userdb, optarg);
      turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_SQLITE;
      break;
#endif
#if !defined(TURN_NO_PQ)
    case 'e':
      STRCPY(turn_params.default_users_db.persistent_users_db.userdb, optarg);
      turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_PQ;
      break;
#endif
#if !defined(TURN_NO_MYSQL)
    case 'M':
      STRCPY(turn_params.default_users_db.persistent_users_db.userdb, optarg);
      turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_MYSQL;
      break;
#endif
#if !defined(TURN_NO_MONGO)
    case 'J':
      STRCPY(turn_params.default_users_db.persistent_users_db.userdb, optarg);
      turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_MONGO;
      break;
#endif
#if !defined(TURN_NO_HIREDIS)
    case 'N':
      STRCPY(turn_params.default_users_db.persistent_users_db.userdb, optarg);
      turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_REDIS;
      break;
#endif
    case 'u':
      STRCPY(user, optarg);
      if (!is_secure_string((uint8_t *)user, 1)) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong user name structure or symbols, choose another name: %s\n", user);
        exit(-1);
      }
      if (SASLprep((uint8_t *)user) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong user name: %s\n", user);
        exit(-1);
      }
      break;
    case 'r':
      set_default_realm_name(optarg);
      STRCPY(realm, optarg);
      if (SASLprep((uint8_t *)realm) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong realm: %s\n", realm);
        exit(-1);
      }
      break;
    case 'p':
      STRCPY(pwd, optarg);
      if (SASLprep((uint8_t *)pwd) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong password: %s\n", pwd);
        exit(-1);
      }
      if (print_enc_password) {
        char result[257];
        generate_new_enc_password((char *)pwd, result);
        printf("%s\n", result);
        exit(0);
      }
      if (print_enc_aes_password) {
        encrypt_aes_128(pwd, generated_key);
        exit(0);
      }
      break;
    case 'x':
      generate_aes_128_key(optarg, generated_key);
      exit(0);
      break;
    case 'f':
      fptr = fopen((char *)optarg, "r");
      if (fptr == NULL) {
        printf("No such file like %s\n", (char *)optarg);
      } else {
        fseek(fptr, 0, SEEK_SET);
        rc = fread(generated_key, sizeof(char), 16, fptr);
        if (rc == 0) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: Secret-Key file is empty\n", __FUNCTION__);
        } else {
          if (rc != 16) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: Secret-Key length is not enough\n", __FUNCTION__);
          }
        }
        fclose(fptr);
      }
      break;
    case 'v':
      decrypt_aes_128((char *)optarg, generated_key);
      exit(0);
    case 'h':
      printf("\n%s\n", AdminUsage);
      exit(0);
      break;
    default:
      fprintf(stderr, "\n%s\n", AdminUsage);
      exit(-1);
    }
  }

#if !defined(TURN_NO_SQLITE)
  if (!strlen(turn_params.default_users_db.persistent_users_db.userdb) &&
      (turn_params.default_users_db.userdb_type == TURN_USERDB_TYPE_SQLITE))
    strncpy(turn_params.default_users_db.persistent_users_db.userdb, DEFAULT_USERDB_FILE, TURN_LONG_STRING_SIZE);
#endif

  if (ct == TA_COMMAND_UNKNOWN) {
    fprintf(stderr, "\n%s\n", AdminUsage);
    exit(-1);
  }

  argc -= optind;
  argv += optind;

  if (argc != 0) {
    fprintf(stderr, "\n%s\n", AdminUsage);
    exit(-1);
  }

  int result = adminuser(user, realm, pwd, secret, origin, ct, &po, is_admin);

  disconnect_database();

  return result;
}

static void print_features(unsigned long mfn) {
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Coturn Version %s\n", TURN_SOFTWARE);
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Max number of open files/sockets allowed for this process: %lu\n", mfn);
  if (turn_params.net_engine_version == NEV_UDP_SOCKET_PER_ENDPOINT)
    mfn = mfn / 3;
  else
    mfn = mfn / 2;
  mfn = ((unsigned long)(mfn / 500)) * 500;
  if (mfn < 500)
    mfn = 500;
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                "Due to the open files/sockets limitation, max supported number of TURN Sessions possible is: %lu "
                "(approximately)\n",
                mfn);

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n\n==== Show him the instruments, Practical Frost: ====\n\n");

  /*
     Frost stepped forward and opened the polished case with a theatrical
     flourish. It was a masterful piece of craftsmanship. As the lid was
     pulled back, the many trays inside lifted and fanned out, displaying
     Glokta’s tools in all their gruesome glory. There were blades of every
     size and shape, needles curved and straight, bottles of oil and acid,
     nails and screws, clamps and pliers, saws, hammers, chisels. Metal, wood
     and glass glittered in the bright lamplight, all polished to mirror
     brightness and honed to a murderous sharpness.
     */

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "OpenSSL compile-time version: %s (0x%lx)\n", OPENSSL_VERSION_TEXT,
                OPENSSL_VERSION_NUMBER);

#if !TLS_SUPPORTED
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TLS is not supported\n");
#elif TLSv1_3_SUPPORTED
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TLS 1.3 supported\n");
#elif TLSv1_2_SUPPORTED
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TLS 1.2 supported\n");
#elif TLSv1_1_SUPPORTED
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TLS 1.1 supported\n");
#elif TLSv1_SUPPORTED
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TLS 1.0 supported\n");
#endif

#if !DTLS_SUPPORTED
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS is not supported\n");
#elif DTLSv1_2_SUPPORTED
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS 1.2 supported\n");
#elif DTLS_SUPPORTED
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS supported\n");
#endif

#if ALPN_SUPPORTED
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TURN/STUN ALPN supported\n");
#else
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TURN/STUN ALPN is not supported\n");
#endif

  if (ENC_ALG_NUM == 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Third-party authorization (oAuth) is not supported\n");
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Third-party authorization (oAuth) supported\n");
#if defined(TURN_NO_GCM)
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "GCM (AEAD) is not supported\n");
#else
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "GCM (AEAD) supported\n");
#endif
  }

#if !defined(TURN_NO_SQLITE)
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SQLite supported, default database location is %s\n", DEFAULT_USERDB_FILE);
#else
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SQLite is not supported\n");
#endif

#if !defined(TURN_NO_HIREDIS)
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Redis supported\n");
#else
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Redis is not supported\n");
#endif

#if !defined(TURN_NO_PQ)
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "PostgreSQL supported\n");
#else
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "PostgreSQL is not supported\n");
#endif

#if !defined(TURN_NO_MYSQL)
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "MySQL supported\n");
#else
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "MySQL is not supported\n");
#endif

#if !defined(TURN_NO_MONGO)
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "MongoDB supported\n");
#else
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "MongoDB is not supported\n");
#endif

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Default Net Engine version: %d (%s)\n", (int)turn_params.net_engine_version,
                turn_params.net_engine_version_txt[(int)turn_params.net_engine_version]);
}

#if defined(__linux__) || defined(__LINUX__) || defined(__linux) || defined(linux__) || defined(LINUX) ||              \
    defined(__LINUX) || defined(LINUX__)
#include <linux/version.h>
#endif

static void set_network_engine(void) {
  if (turn_params.net_engine_version != NEV_UNKNOWN)
    return;
  turn_params.net_engine_version = NEV_UDP_SOCKET_PER_ENDPOINT;
#if defined(SO_REUSEPORT)
#if defined(__linux__) || defined(__LINUX__) || defined(__linux) || defined(linux__) || defined(LINUX) ||              \
    defined(__LINUX) || defined(LINUX__)
  turn_params.net_engine_version = NEV_UDP_SOCKET_PER_THREAD;
#else  /* BSD ? */
  turn_params.net_engine_version = NEV_UDP_SOCKET_PER_SESSION;
#endif /* Linux */
#else  /* defined(SO_REUSEPORT) */
#if defined(__linux__) || defined(__LINUX__) || defined(__linux) || defined(linux__) || defined(LINUX) ||              \
    defined(__LINUX) || defined(LINUX__)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
  // net_engine_version = NEV_UDP_SOCKET_PER_SESSION;
  turn_params.net_engine_version = NEV_UDP_SOCKET_PER_ENDPOINT;
#else
  turn_params.net_engine_version = NEV_UDP_SOCKET_PER_ENDPOINT;
#endif /* Linux version */
#endif /* Linux */
#endif /* defined(SO_REUSEPORT) */
}

static void drop_privileges(void) {
#if defined(WINDOWS)
  // TODO: implement it!!!
#else
  setgroups(0, NULL);
  if (procgroupid_set) {
    if (getgid() != procgroupid) {
      if (setgid(procgroupid) != 0) {
        perror("setgid: Unable to change group privileges");
        exit(-1);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "New GID: %s(%lu)\n", procgroupname, (unsigned long)procgroupid);
      }
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Keep GID: %s(%lu)\n", procgroupname, (unsigned long)procgroupid);
    }
  }

  if (procuserid_set) {
    if (procuserid != getuid()) {
      if (setuid(procuserid) != 0) {
        perror("setuid: Unable to change user privileges");
        exit(-1);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "New UID: %s(%lu)\n", procusername, (unsigned long)procuserid);
      }
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Keep UID: %s(%lu)\n", procusername, (unsigned long)procuserid);
    }
  }
#endif
}

static void init_domain(void) {
#if !defined(TURN_NO_GETDOMAINNAME)
  if (getdomainname(turn_params.domain, sizeof(turn_params.domain) - 1) < 0) {
    turn_params.domain[0] = 0;
  } else if (!strcmp(turn_params.domain, "(none)")) {
    turn_params.domain[0] = 0;
  }
#endif
}

int main(int argc, char **argv) {
  int c = 0;

  IS_TURN_SERVER = 1;

  TURN_MUTEX_INIT(&turn_params.tls_mutex);

  set_execdir();

  init_super_memory();

  init_domain();
  create_default_realm();

  init_turn_server_addrs_list(&turn_params.alternate_servers_list);
  init_turn_server_addrs_list(&turn_params.tls_alternate_servers_list);
  init_turn_server_addrs_list(&turn_params.aux_servers_list);

  set_network_engine();

  init_listener();
  init_secrets_list(&turn_params.default_users_db.ram_db.static_auth_secrets);
  init_dynamic_ip_lists();

  if (!strstr(argv[0], "turnadmin")) {

    struct uoptions uo;
    uo.u.m = long_options;

    while (((c = getopt_long(argc, argv, OPTIONS, uo.u.o, NULL)) != -1)) {
      switch (c) {
      case 'l':
        set_logfile(optarg);
        break;
      case NO_STDOUT_LOG_OPT:
        set_no_stdout_log(get_bool_value(optarg));
        break;
      case SYSLOG_OPT:
        set_log_to_syslog(get_bool_value(optarg));
        break;
      case SIMPLE_LOG_OPT:
        set_simple_log(get_bool_value(optarg));
        break;
      case NEW_LOG_TIMESTAMP_OPT:
        use_new_log_timestamp_format = 1;
        break;
      case NEW_LOG_TIMESTAMP_FORMAT_OPT:
        set_turn_log_timestamp_format(optarg);
        break;
      case SYSLOG_FACILITY_OPT:
        set_syslog_facility(optarg);
        break;
      default:;
      }
    }
  }

  optind = 0;

#if !TLS_SUPPORTED
  turn_params.no_tls = 1;
#endif

#if !DTLS_SUPPORTED
  turn_params.no_dtls = 1;
#endif

  {
    int cpus = get_system_number_of_cpus();
    if (0 < cpus)
      turn_params.cpus = get_system_number_of_cpus();
    if (turn_params.cpus < DEFAULT_CPUS_NUMBER)
      turn_params.cpus = DEFAULT_CPUS_NUMBER;
    else if (turn_params.cpus > MAX_NUMBER_OF_GENERAL_RELAY_SERVERS)
      turn_params.cpus = MAX_NUMBER_OF_GENERAL_RELAY_SERVERS;

    turn_params.general_relay_servers_number = (turnserver_id)turn_params.cpus;

    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "System cpu num is %lu\n", turn_params.cpus);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "System enable num is %lu\n", get_system_active_number_of_cpus());
  }

  memset(&turn_params.default_users_db, 0, sizeof(default_users_db_t));
  turn_params.default_users_db.ram_db.static_accounts = ur_string_map_create(free);

  if (strstr(argv[0], "turnadmin"))
    return adminmain(argc, argv);
  // Zero pass apply the log options.
  read_config_file(argc, argv, 0);
  // First pass read other config options
  read_config_file(argc, argv, 1);

  struct uoptions uo;
  uo.u.m = long_options;

  while (((c = getopt_long(argc, argv, OPTIONS, uo.u.o, NULL)) != -1)) {
    if (c != 'u')
      set_option(c, optarg);
  }

  // Second pass read -u options
  read_config_file(argc, argv, 2);

  {
    unsigned long mfn = set_system_parameters(1);

    print_features(mfn);
  }

  if (!get_realm(NULL)->options.name[0]) {
    STRCPY(get_realm(NULL)->options.name, turn_params.domain);
  }

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Domain name: %s\n", turn_params.domain);
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Default realm: %s\n", get_realm(NULL)->options.name);

  if (turn_params.acme_redirect[0]) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ACME redirect URL: %s\n", turn_params.acme_redirect);
  }
  if (turn_params.oauth && turn_params.oauth_server_name[0]) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "oAuth server name: %s\n", turn_params.oauth_server_name);
  }

  optind = 0;

  while (((c = getopt_long(argc, argv, OPTIONS, uo.u.o, NULL)) != -1)) {
    if (c == 'u') {
      set_option(c, optarg);
    }
  }

  if (turn_params.bps_capacity && !(turn_params.max_bps)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                  "\nCONFIG ERROR: If you set the --bps-capacity option, then you must set --max-bps options, too.\n");
    exit(-1);
  }

  if (turn_params.no_udp_relay && turn_params.no_tcp_relay) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                  "\nCONFIG ERROR: --no-udp-relay and --no-tcp-relay options cannot be used together.\n");
    exit(-1);
  }

  if (turn_params.no_udp_relay) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "CONFIG: --no-udp-relay: UDP relay endpoints are not allowed.\n");
  }

  if (turn_params.no_tcp_relay) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "CONFIG: --no-tcp-relay: TCP relay endpoints are not allowed.\n");
  }

  if (turn_params.server_relay) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "CONFIG: WARNING: --server-relay: NON-STANDARD AND DANGEROUS OPTION.\n");
  }

#if !defined(TURN_NO_SQLITE)
  if (!strlen(turn_params.default_users_db.persistent_users_db.userdb) &&
      (turn_params.default_users_db.userdb_type == TURN_USERDB_TYPE_SQLITE))
    strncpy(turn_params.default_users_db.persistent_users_db.userdb, DEFAULT_USERDB_FILE, TURN_LONG_STRING_SIZE);
#endif

  argc -= optind;
  argv += optind;

  if (argc > 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "CONFIG: Unknown argument: %s\n", argv[argc - 1]);
  }

  if (use_lt_credentials && anon_credentials) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "CONFIG: -a and -z options cannot be used together.\n");
    exit(-1);
  }

  if (use_ltc && use_tltc) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                  "CONFIG: You specified --lt-cred-mech and --use-auth-secret in the same time.\n"
                  "Be aware that you could not mix the username/password and the shared secret based auth methods. \n"
                  "Shared secret overrides username/password based auth method. Check your configuration!\n");
  }

  if (turn_params.allow_loopback_peers) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                  "CONFIG: allow_loopback_peers opens a possible security vulnerability. Do not use in production!!\n");
    if (cli_password[0] == 0 && use_cli) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                    "CONFIG: allow_loopback_peers and empty cli password cannot be used together.\n");
      exit(-1);
    }
  }

  if (use_cli && cli_password[0] == 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "CONFIG: Empty cli-password, and so telnet cli interface is disabled! "
                                        "Please set a non empty cli-password!\n");
    use_cli = 0;
  }

  if (!use_lt_credentials && !anon_credentials) {
    if (turn_params.default_users_db.ram_db.users_number) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                    "CONFIG: you specified long-term user accounts, (-u option) \n	but you did "
                    "not specify the long-term credentials option\n	(-a or --lt-cred-mech option).\n 	I am "
                    "turning --lt-cred-mech ON for you, but double-check your configuration.\n");
      turn_params.ct = TURN_CREDENTIALS_LONG_TERM;
      use_lt_credentials = 1;
    } else {
      turn_params.ct = TURN_CREDENTIALS_NONE;
      use_lt_credentials = 0;
    }
  }

  if (use_lt_credentials) {
    if (!get_realm(NULL)->options.name[0]) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                    "CONFIG: you did specify the long-term credentials usage\n but you did not specify "
                    "the default realm option (-r option).\n		Check your configuration.\n");
    }
  }

  if (anon_credentials) {
    if (turn_params.default_users_db.ram_db.users_number) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                    "CONFIG: you specified user accounts, (-u option)	but you also specified the "
                    "anonymous user access option (-z or --no-auth option).	User accounts will be ignored.\n");
      turn_params.ct = TURN_CREDENTIALS_NONE;
      use_lt_credentials = 0;
    }
  }

  openssl_setup();

  int local_listeners = 0;
  if (!turn_params.listener.addrs_number) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "NO EXPLICIT LISTENER ADDRESS(ES) ARE CONFIGURED\n");
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "===========Discovering listener addresses: =========\n");
    int maddrs = make_local_listeners_list();
    if ((maddrs < 1) || !turn_params.listener.addrs_number) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot configure any meaningful IP listener address\n", __FUNCTION__);
      fprintf(stderr, "\n%s\n", Usage);
      exit(-1);
    }
    local_listeners = 1;
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "=====================================================\n");
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total: %d 'real' addresses discovered\n", maddrs);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "=====================================================\n");
  }

  if (!turn_params.relays_number) {
    if (!local_listeners && turn_params.listener.addrs_number && turn_params.listener.addrs) {
      size_t la = 0;
      for (la = 0; la < turn_params.listener.addrs_number; la++) {
        if (turn_params.listener.addrs[la]) {
          add_relay_addr(turn_params.listener.addrs[la]);
        }
      }
    }
    if (!turn_params.relays_number) {
      turn_params.default_relays = 1;
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "NO EXPLICIT RELAY ADDRESS(ES) ARE CONFIGURED\n");
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "===========Discovering relay addresses: =============\n");
      if (make_local_relays_list(0, AF_INET) < 1) {
        make_local_relays_list(1, AF_INET);
      }
      if (make_local_relays_list(0, AF_INET6) < 1) {
        make_local_relays_list(1, AF_INET6);
      }
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "=====================================================\n");
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total: %d relay addresses discovered\n", (int)turn_params.relays_number);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "=====================================================\n");
    }

    if (!turn_params.relays_number) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: You must specify the relay address(es)\n", __FUNCTION__);
      fprintf(stderr, "\n%s\n", Usage);
      exit(-1);
    }
  }

  if (turn_params.external_ip && turn_params.relay_addrs) {
    size_t ir = 0;
    for (ir = 0; ir < turn_params.relays_number; ++ir) {
      if (turn_params.relay_addrs[ir]) {
        const char *sra = (const char *)turn_params.relay_addrs[ir];
        if ((strstr(sra, "127.0.0.1") != sra) && (strstr(sra, "::1") != sra)) {
          ioa_addr ra;
          if (make_ioa_addr((const uint8_t *)sra, 0, &ra) < 0) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "-X : Wrong address format: %s\n", sra);
          } else if (ra.ss.sa_family == turn_params.external_ip->ss.sa_family) {
            ioa_addr_add_mapping(turn_params.external_ip, &ra);
          }
        }
      }
    }
  }

  if (socket_init())
    return -1;

#if defined(WINDOWS)

    // TODO: implement deamon!!! use windows server
#else
  if (turn_params.turn_daemon) {
#if !defined(TURN_HAS_DAEMON)
    pid_t pid = fork();
    if (pid > 0)
      exit(0);
    if (pid < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot start daemon process\n");
      exit(-1);
    }
#else
    if (daemon(1, 0) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot start daemon process\n");
      exit(-1);
    }
    reset_rtpprintf();
#endif
  }

  if (turn_params.pidfile[0]) {

    char s[2049];
    FILE *f = fopen(turn_params.pidfile, "w");
    if (f) {
      STRCPY(s, turn_params.pidfile);
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Cannot create pid file: %s\n", turn_params.pidfile);

      {
        const char *pfs[] = {"/var/run/turnserver.pid",
                             "/var/spool/turnserver.pid",
                             "/var/turnserver.pid",
                             "/var/tmp/turnserver.pid",
                             "/tmp/turnserver.pid",
                             "turnserver.pid",
                             NULL};
        const char **ppfs = pfs;
        while (*ppfs) {
          f = fopen(*ppfs, "w");
          if (f) {
            STRCPY(s, *ppfs);
            break;
          } else {
            ++ppfs;
          }
        }
      }
    }

    if (f) {
      fprintf(f, "%lu\n", (unsigned long)getpid());
      fclose(f);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "pid file created: %s\n", s);
    }
  }
#endif

  setup_server();

#if defined(WINDOWS)
  // TODO: implement it!!! add windows server
#else
  struct event *ev = evsignal_new(turn_params.listener.event_base, SIGUSR2, reload_ssl_certs, NULL);
  event_add(ev, NULL);

  ev = evsignal_new(turn_params.listener.event_base, SIGTERM, shutdown_handler, NULL);
  event_add(ev, NULL);
  ev = evsignal_new(turn_params.listener.event_base, SIGINT, shutdown_handler, NULL);
  event_add(ev, NULL);
#endif

  drop_privileges();
  start_prometheus_server();

  run_listener_server(&(turn_params.listener));

  disconnect_database();

  return 0;
}

////////// OpenSSL locking ////////////////////////////////////////

#if defined(OPENSSL_THREADS)
#if OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0

// array larger than anything that OpenSSL may need:
static TURN_MUTEX_DECLARE(mutex_buf[256]);
static int mutex_buf_initialized = 0;

void coturn_locking_function(int mode, int n, const char *file, int line);
void coturn_locking_function(int mode, int n, const char *file, int line) {
  UNUSED_ARG(file);
  UNUSED_ARG(line);
  if (mutex_buf_initialized && (n < CRYPTO_num_locks())) {
    if (mode & CRYPTO_LOCK)
      TURN_MUTEX_LOCK(&(mutex_buf[n]));
    else
      TURN_MUTEX_UNLOCK(&(mutex_buf[n]));
  }
}

void coturn_id_function(CRYPTO_THREADID *ctid);
void coturn_id_function(CRYPTO_THREADID *ctid) {
  UNUSED_ARG(ctid);
  CRYPTO_THREADID_set_numeric(ctid, (unsigned long)pthread_self());
}

static int THREAD_setup(void) {
  int i;
  for (i = 0; i < CRYPTO_num_locks(); i++) {
    TURN_MUTEX_INIT(&(mutex_buf[i]));
  }

  mutex_buf_initialized = 1;
  CRYPTO_THREADID_set_callback(coturn_id_function);
  CRYPTO_set_locking_callback(coturn_locking_function);
  return 1;
}

int THREAD_cleanup(void) {
  int i;

  if (!mutex_buf_initialized)
    return 0;

  CRYPTO_THREADID_set_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i = 0; i < CRYPTO_num_locks(); i++) {
    TURN_MUTEX_DESTROY(&(mutex_buf[i]));
  }

  mutex_buf_initialized = 0;
  return 1;
}
#else
static int THREAD_setup(void) { return 1; }

int THREAD_cleanup(void);
int THREAD_cleanup(void) { return 1; }
#endif /* OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_1_1_0 */
#endif /* defined(OPENSSL_THREADS) */

static void adjust_key_file_name(char *fn, const char *file_title, int critical) {
  char *full_path_to_file = NULL;

  if (!fn[0]) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "\nERROR: you must set the %s file parameter\n", file_title);
    goto keyerr;
  } else {

    full_path_to_file = find_config_file(fn, 1);
    {
      FILE *f = full_path_to_file ? fopen(full_path_to_file, "r") : NULL;
      if (!f) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "cannot find %s file: %s (1)\n", file_title, fn);
        goto keyerr;
      } else {
        fclose(f);
      }
    }

    if (!full_path_to_file) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "cannot find %s file: %s (2)\n", file_title, fn);
      goto keyerr;
    }

    strncpy(fn, full_path_to_file, sizeof(turn_params.cert_file) - 1);
    fn[sizeof(turn_params.cert_file) - 1] = 0;

    free(full_path_to_file);
    return;
  }

keyerr : {
  if (critical) {
    turn_params.no_tls = 1;
    turn_params.no_dtls = 1;
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "cannot start TLS and DTLS listeners because %s file is not set properly\n",
                  file_title);
  }
  if (full_path_to_file)
    free(full_path_to_file);
  return;
}
}

static void adjust_key_file_names(void) {
  if (turn_params.ca_cert_file[0])
    adjust_key_file_name(turn_params.ca_cert_file, "CA", 1);
  adjust_key_file_name(turn_params.cert_file, "certificate", 1);
  adjust_key_file_name(turn_params.pkey_file, "private key", 1);
  if (turn_params.dh_file[0])
    adjust_key_file_name(turn_params.dh_file, "DH key", 0);
}
static DH *get_dh566(void) {

  unsigned char dh566_p[] = {0x36, 0x53, 0xA8, 0x9C, 0x3C, 0xF1, 0xD1, 0x1B, 0x2D, 0xA2, 0x64, 0xDE, 0x59, 0x3B, 0xE3,
                             0x8C, 0x27, 0x74, 0xC2, 0xBE, 0x9B, 0x6D, 0x56, 0xE7, 0xDF, 0xFF, 0x67, 0x6A, 0xD2, 0x0C,
                             0xE8, 0x9E, 0x52, 0x00, 0x05, 0xB3, 0x53, 0xF7, 0x1C, 0x41, 0xB2, 0xAC, 0x38, 0x16, 0x32,
                             0x3A, 0x8E, 0x90, 0x6C, 0x7E, 0xD1, 0x44, 0xCB, 0xF9, 0x2D, 0x1E, 0x4A, 0x9A, 0x32, 0x81,
                             0x58, 0xE1, 0xE1, 0x17, 0xC1, 0x9C, 0xF1, 0x1E, 0x96, 0x2D, 0x5F};

  //	-----BEGIN DH PARAMETERS-----
  // MEwCRzZTqJw88dEbLaJk3lk744wndMK+m21W59//Z2rSDOieUgAFs1P3HEGyrDgW
  // MjqOkGx+0UTL+S0eSpoygVjh4RfBnPEeli1fAgEF
  //	-----END DH PARAMETERS-----

  unsigned char dh566_g[] = {0x05};
  DH *dh;

  if ((dh = DH_new()) == NULL)
    return (NULL);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  dh->p = BN_bin2bn(dh566_p, sizeof(dh566_p), NULL);
  dh->g = BN_bin2bn(dh566_g, sizeof(dh566_g), NULL);
  if ((dh->p == NULL) || (dh->g == NULL)) {
    DH_free(dh);
    return (NULL);
  }
#else
  DH_set0_pqg(dh, BN_bin2bn(dh566_p, sizeof(dh566_p), NULL), NULL, BN_bin2bn(dh566_g, sizeof(dh566_g), NULL));
#endif
  return (dh);
}

static DH *get_dh1066(void) {

  unsigned char dh1066_p[] = {0x02, 0x0E, 0x26, 0x6F, 0xAA, 0x9F, 0xA8, 0xE5, 0x3F, 0x70, 0x88, 0xF1, 0xA9, 0x29, 0xAE,
                              0x1A, 0x2B, 0xA8, 0x2F, 0xE8, 0xE5, 0x0E, 0x81, 0x78, 0xD7, 0x12, 0x41, 0xDC, 0xE2, 0xD5,
                              0x10, 0x6F, 0x8A, 0x35, 0x23, 0xCE, 0x66, 0x93, 0x67, 0x14, 0xEA, 0x0A, 0x61, 0xD4, 0x43,
                              0x63, 0x5C, 0xDF, 0xDE, 0xF5, 0xB9, 0xC6, 0xB4, 0x8C, 0xBA, 0x1A, 0x25, 0x9F, 0x73, 0x0F,
                              0x1E, 0x1A, 0x97, 0x42, 0x2E, 0x60, 0x9E, 0x4C, 0x3C, 0x70, 0x6A, 0xFB, 0xDD, 0xAA, 0x7A,
                              0x48, 0xA5, 0x1E, 0x87, 0xC8, 0xA3, 0x5E, 0x26, 0x40, 0x1B, 0xDE, 0x08, 0x5E, 0xA2, 0xB8,
                              0xE8, 0x76, 0x43, 0xE8, 0xF1, 0x4B, 0x35, 0x4C, 0x38, 0x92, 0xB9, 0xFF, 0x61, 0xE6, 0x6C,
                              0xBA, 0xF9, 0x16, 0x36, 0x3C, 0x69, 0x2D, 0x57, 0x90, 0x62, 0x8A, 0xD0, 0xD4, 0xFB, 0xB2,
                              0x5A, 0x61, 0x99, 0xA9, 0xE8, 0x93, 0x80, 0xA2, 0xB7, 0xDC, 0xB1, 0x6A, 0xAF, 0xE3};

  //	-----BEGIN DH PARAMETERS-----
  //	MIGMAoGGAg4mb6qfqOU/cIjxqSmuGiuoL+jlDoF41xJB3OLVEG+KNSPOZpNnFOoK
  //	YdRDY1zf3vW5xrSMuholn3MPHhqXQi5gnkw8cGr73ap6SKUeh8ijXiZAG94IXqK4
  //	6HZD6PFLNUw4krn/YeZsuvkWNjxpLVeQYorQ1PuyWmGZqeiTgKK33LFqr+MCAQI=
  //	-----END DH PARAMETERS-----

  unsigned char dh1066_g[] = {0x02};
  DH *dh;

  if ((dh = DH_new()) == NULL)
    return (NULL);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  dh->p = BN_bin2bn(dh1066_p, sizeof(dh1066_p), NULL);
  dh->g = BN_bin2bn(dh1066_g, sizeof(dh1066_g), NULL);
  if ((dh->p == NULL) || (dh->g == NULL)) {
    DH_free(dh);
    return (NULL);
  }
#else
  DH_set0_pqg(dh, BN_bin2bn(dh1066_p, sizeof(dh1066_p), NULL), NULL, BN_bin2bn(dh1066_g, sizeof(dh1066_g), NULL));
#endif
  return (dh);
}

static DH *get_dh2066(void) {

  unsigned char dh2066_p[] = {
      0x03, 0x31, 0x77, 0x20, 0x58, 0xA6, 0x69, 0xA3, 0x9D, 0x2D, 0x5E, 0xE0, 0x5C, 0x46, 0x82, 0x0F, 0x9E, 0x80, 0xF0,
      0x00, 0x2A, 0xF9, 0x0F, 0x62, 0x1F, 0x89, 0xCE, 0x7D, 0x2A, 0xFD, 0xC5, 0x9A, 0x7C, 0x6A, 0x60, 0x2C, 0xF1, 0xDD,
      0xD4, 0x4D, 0x6B, 0xCD, 0xE9, 0x95, 0xDB, 0x42, 0x97, 0xBA, 0xE4, 0xAF, 0x41, 0x38, 0x8F, 0x57, 0x31, 0xA4, 0x39,
      0xDD, 0x31, 0xC3, 0x6F, 0x98, 0x0E, 0xE3, 0xB1, 0x43, 0xD1, 0x36, 0xB0, 0x01, 0x28, 0x42, 0x71, 0xD3, 0xB0, 0x36,
      0xA0, 0x47, 0x99, 0x25, 0x9B, 0x32, 0xF5, 0x86, 0xB1, 0x13, 0x5C, 0x24, 0x8D, 0x8D, 0x7F, 0xE2, 0x7F, 0x9A, 0xC1,
      0x52, 0x58, 0xC0, 0x63, 0xAA, 0x00, 0x7C, 0x1F, 0x11, 0xBD, 0xAC, 0x4C, 0x2D, 0xE0, 0xA2, 0x9D, 0x4E, 0x21, 0xE4,
      0x0B, 0xCD, 0x24, 0x92, 0xD2, 0x37, 0x27, 0x84, 0x59, 0x90, 0x46, 0x2F, 0xD5, 0xB9, 0x27, 0x93, 0x18, 0x88, 0xBD,
      0x91, 0x5B, 0x87, 0x55, 0x56, 0xD8, 0x1B, 0xE4, 0xCF, 0x1C, 0xAA, 0xBC, 0xCF, 0x80, 0x1E, 0x35, 0x2D, 0xB1, 0xBC,
      0x35, 0x31, 0x92, 0x62, 0x3C, 0x91, 0x8D, 0x62, 0xDA, 0xCF, 0x83, 0x63, 0x12, 0x4B, 0x30, 0x80, 0xEE, 0x82, 0x3C,
      0x2C, 0xD2, 0x17, 0x13, 0x1F, 0xF9, 0x62, 0x33, 0x5C, 0x63, 0xD8, 0x75, 0x5B, 0xAA, 0x16, 0x5A, 0x36, 0x49, 0x17,
      0x77, 0xB7, 0x74, 0xBD, 0x3E, 0x3F, 0x98, 0x20, 0x59, 0x5E, 0xC7, 0x72, 0xE8, 0xA3, 0x89, 0x21, 0xB4, 0x3C, 0x25,
      0xF4, 0xF4, 0x21, 0x96, 0x5A, 0xA6, 0x77, 0xFF, 0x2C, 0x3A, 0xFC, 0x98, 0x5F, 0xC1, 0xBF, 0x2A, 0xCF, 0xB8, 0x62,
      0x67, 0x23, 0xE8, 0x2F, 0xCC, 0x7B, 0x32, 0x1B, 0x6B, 0x33, 0x67, 0x0A, 0xCB, 0xD0, 0x1F, 0x65, 0xD7, 0x84, 0x54,
      0xF6, 0xF1, 0x88, 0xB5, 0xBB, 0x0C, 0x63, 0x65, 0x34, 0xE4, 0x66, 0x4B};

  //	-----BEGIN DH PARAMETERS-----
  // MIIBCgKCAQMDMXcgWKZpo50tXuBcRoIPnoDwACr5D2Ific59Kv3FmnxqYCzx3dRN
  // a83pldtCl7rkr0E4j1cxpDndMcNvmA7jsUPRNrABKEJx07A2oEeZJZsy9YaxE1wk
  // jY1/4n+awVJYwGOqAHwfEb2sTC3gop1OIeQLzSSS0jcnhFmQRi/VuSeTGIi9kVuH
  // VVbYG+TPHKq8z4AeNS2xvDUxkmI8kY1i2s+DYxJLMIDugjws0hcTH/liM1xj2HVb
  // qhZaNkkXd7d0vT4/mCBZXsdy6KOJIbQ8JfT0IZZapnf/LDr8mF/BvyrPuGJnI+gv
  // zHsyG2szZwrL0B9l14RU9vGItbsMY2U05GZLAgEF
  //	-----END DH PARAMETERS-----

  unsigned char dh2066_g[] = {0x05};
  DH *dh;

  if ((dh = DH_new()) == NULL)
    return (NULL);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  dh->p = BN_bin2bn(dh2066_p, sizeof(dh2066_p), NULL);
  dh->g = BN_bin2bn(dh2066_g, sizeof(dh2066_g), NULL);
  if ((dh->p == NULL) || (dh->g == NULL)) {
    DH_free(dh);
    return (NULL);
  }
#else
  DH_set0_pqg(dh, BN_bin2bn(dh2066_p, sizeof(dh2066_p), NULL), NULL, BN_bin2bn(dh2066_g, sizeof(dh2066_g), NULL));
#endif
  return (dh);
}

static int pem_password_func(char *buf, int size, int rwflag, void *password) {
  UNUSED_ARG(rwflag);

  strncpy(buf, (char *)(password), size);
  buf[size - 1] = 0;
  return (strlen(buf));
}

#if ALPN_SUPPORTED

static int ServerALPNCallback(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                              unsigned int inlen, void *arg) {

  UNUSED_ARG(ssl);
  UNUSED_ARG(arg);

  unsigned char sa_len = (unsigned char)strlen(STUN_ALPN);
  unsigned char ta_len = (unsigned char)strlen(TURN_ALPN);
  unsigned char ha_len = (unsigned char)strlen(HTTP_ALPN);

  int found_http = 0;

  const unsigned char *ptr = in;
  while (ptr < (in + inlen)) {
    unsigned char current_len = *ptr;
    if (ptr + 1 + current_len > in + inlen)
      break;
    if ((!turn_params.no_stun) && (current_len == sa_len) && (memcmp(ptr + 1, STUN_ALPN, sa_len) == 0)) {
      *out = ptr + 1;
      *outlen = sa_len;
      SSL_set_app_data(ssl, STUN_ALPN);
      return SSL_TLSEXT_ERR_OK;
    }
    if ((!turn_params.stun_only) && (current_len == ta_len) && (memcmp(ptr + 1, TURN_ALPN, ta_len) == 0)) {
      *out = ptr + 1;
      *outlen = ta_len;
      SSL_set_app_data(ssl, TURN_ALPN);
      return SSL_TLSEXT_ERR_OK;
    }
    if ((current_len == ha_len) && (memcmp(ptr + 1, HTTP_ALPN, ha_len) == 0)) {
      *out = ptr + 1;
      *outlen = ha_len;
      SSL_set_app_data(ssl, HTTP_ALPN);
      found_http = 1;
    }
    ptr += 1 + current_len;
  }

  if (found_http)
    return SSL_TLSEXT_ERR_OK;

  return SSL_TLSEXT_ERR_NOACK; //???
}

#endif

static void set_ctx(SSL_CTX **out, const char *protocol, const SSL_METHOD *method) {
  SSL_CTX *ctx = SSL_CTX_new(method);
  int err = 0;
  int rc = 0;
#if ALPN_SUPPORTED
  SSL_CTX_set_alpn_select_cb(ctx, ServerALPNCallback, NULL);
#endif

  SSL_CTX_set_default_passwd_cb_userdata(ctx, turn_params.tls_password);

  SSL_CTX_set_default_passwd_cb(ctx, pem_password_func);

  if (!(turn_params.cipher_list[0])) {
    strncpy(turn_params.cipher_list, DEFAULT_CIPHER_LIST, TURN_LONG_STRING_SIZE);
#if defined(DEFAULT_CIPHERSUITES)
    strncat(turn_params.cipher_list, ":", TURN_LONG_STRING_SIZE - strlen(turn_params.cipher_list));
    strncat(turn_params.cipher_list, DEFAULT_CIPHERSUITES, TURN_LONG_STRING_SIZE - strlen(turn_params.cipher_list));
#endif
  }

  SSL_CTX_set_cipher_list(ctx, turn_params.cipher_list);
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

#if TLSv1_3_SUPPORTED
  SSL_CTX_set_ciphersuites(ctx, turn_params.cipher_list);
#endif

  if (!SSL_CTX_use_certificate_chain_file(ctx, turn_params.cert_file)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: no certificate found\n", protocol);
    err = 1;
  }

  if (!SSL_CTX_use_PrivateKey_file(ctx, turn_params.pkey_file, SSL_FILETYPE_PEM)) {
    if (!SSL_CTX_use_RSAPrivateKey_file(ctx, turn_params.pkey_file, SSL_FILETYPE_PEM)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                    "%s: ERROR: no valid private key found, or invalid private key password provided\n", protocol);
      err = 1;
    }
  }
  if (!SSL_CTX_check_private_key(ctx)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: invalid private key\n", protocol);
    err = 1;
  }

  if (turn_params.ca_cert_file[0]) {

    if (!SSL_CTX_load_verify_locations(ctx, turn_params.ca_cert_file, NULL)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot load CA from file: %s\n", turn_params.ca_cert_file);
      err = 1;
    }

    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(turn_params.ca_cert_file));

    /* Set to require peer (client) certificate verification */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, NULL);

    /* Set the verification depth to 9 */
    SSL_CTX_set_verify_depth(ctx, 9);

  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  }

#if !defined(OPENSSL_NO_EC) && defined(OPENSSL_EC_NAMED_CURVE)
  { // Elliptic curve algorithms:
    int nid = 0;
    int set_auto_curve = 0;

    const char *curve_name = turn_params.ec_curve_name;

    if (!(curve_name[0])) {
#if !SSL_SESSION_ECDH_AUTO_SUPPORTED
      curve_name = DEFAULT_EC_CURVE_NAME;
#endif
      set_auto_curve = 1;
    }

    if (curve_name[0]) {
      {
        nid = OBJ_sn2nid(curve_name);
        if (nid == 0) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "unknown curve name: %s\n", curve_name);
          curve_name = DEFAULT_EC_CURVE_NAME;
          nid = OBJ_sn2nid(curve_name);
          set_auto_curve = 1;
        }
      }

      {
        EC_KEY *ecdh = EC_KEY_new_by_curve_name(nid);
        if (!ecdh) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: allocate EC suite\n", __FUNCTION__);
          set_auto_curve = 1;
        } else {
          SSL_CTX_set_tmp_ecdh(ctx, ecdh);
          EC_KEY_free(ecdh);
        }
      }
    }

    if (set_auto_curve) {
#if SSL_SESSION_ECDH_AUTO_SUPPORTED
#if OPENSSL_VERSION_NUMBER < 0x10100000L
      SSL_CTX_set_ecdh_auto(ctx, 1);
#endif
#endif
      set_auto_curve = 0;
    }
  }
#endif

  { // DH algorithms:

    DH *dh = NULL;
    if (turn_params.dh_file[0]) {
      FILE *paramfile = fopen(turn_params.dh_file, "r");
      if (!paramfile) {
        perror("Cannot open DH file");
      } else {
        dh = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
        fclose(paramfile);
        if (dh) {
          turn_params.dh_key_size = DH_CUSTOM;
        }
      }
    }

    if (!dh) {
      if (turn_params.dh_key_size == DH_566)
        dh = get_dh566();
      else if (turn_params.dh_key_size == DH_1066)
        dh = get_dh1066();
      else
        dh = get_dh2066();
    }

    if (!dh) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: cannot allocate DH suite\n", __FUNCTION__);
      err = 1;
    } else {
      if (1 != SSL_CTX_set_tmp_dh(ctx, dh)) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: cannot set DH\n", __FUNCTION__);
        err = 1;
      }
      DH_free(dh);
    }
  }

  { // secret key

    if (turn_params.secret_key_file[0]) {
      FILE *f = fopen(turn_params.secret_key_file, "r");

      if (!f) {
        perror("Cannot open Secret-Key file");
      } else {
        fseek(f, 0, SEEK_SET);
        rc = fread(turn_params.secret_key, sizeof(char), 16, f);
        if (rc == 0) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: Secret-Key file is empty\n", __FUNCTION__);
        } else {
          if (rc != 16) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: ERROR: Secret-Key length is not enough\n", __FUNCTION__);
          }
        }
        fclose(f);
      }
    }
  }

  {
    int op = 0;

#if defined(SSL_OP_NO_SSLv2)
    op |= SSL_OP_NO_SSLv2;
#endif

#if defined(SSL_OP_NO_SSLv3)
    op |= SSL_OP_NO_SSLv3;
#endif

#if defined(SSL_OP_CIPHER_SERVER_PREFERENCE)
    op |= SSL_OP_CIPHER_SERVER_PREFERENCE;
#endif

#if defined(SSL_OP_SINGLE_DH_USE)
    op |= SSL_OP_SINGLE_DH_USE;
#endif

#if defined(SSL_OP_SINGLE_ECDH_USE)
    op |= SSL_OP_SINGLE_ECDH_USE;
#endif

    SSL_CTX_set_options(ctx, op);
  }

  if (*out == NULL) {
    // Always initialize, even if issues were encountered
    *out = ctx;
  } else if (!err) {
    SSL_CTX_free(*out);
    *out = ctx;
  }
}

static void openssl_load_certificates(void);
static void openssl_setup(void) {
  THREAD_setup();
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

#if !TLS_SUPPORTED
  if (!turn_params.no_tls) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "WARNING: TLS is not supported\n");
    turn_params.no_tls = 1;
  }
#endif

  if (!(turn_params.no_tls && turn_params.no_dtls) && !turn_params.cert_file[0]) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "\nWARNING: certificate file is not specified, I cannot start TLS/DTLS "
                                          "services.\nOnly 'plain' UDP/TCP listeners can be started.\n");
    turn_params.no_tls = 1;
    turn_params.no_dtls = 1;
  }

  if (!(turn_params.no_tls && turn_params.no_dtls) && !turn_params.pkey_file[0]) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "\nWARNING: private key file is not specified, I cannot start TLS/DTLS "
                                          "services.\nOnly 'plain' UDP/TCP listeners can be started.\n");
    turn_params.no_tls = 1;
    turn_params.no_dtls = 1;
  }

  if (!(turn_params.no_tls && turn_params.no_dtls)) {
    adjust_key_file_names();
  }

  openssl_load_certificates();
}

static void openssl_load_certificates(void) {

  print_abs_file_name("", "Certificate", turn_params.cert_file);
  print_abs_file_name("", "Private key", turn_params.pkey_file);

  TURN_MUTEX_LOCK(&turn_params.tls_mutex);
  if (!turn_params.no_tls) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    set_ctx(&turn_params.tls_ctx, "TLS", TLSv1_2_server_method()); /*openssl-1.0.2 version specific API */
    if (turn_params.no_tlsv1) {
      SSL_CTX_set_options(turn_params.tls_ctx, SSL_OP_NO_TLSv1);
    }
#if TLSv1_1_SUPPORTED
    if (turn_params.no_tlsv1_1) {
      SSL_CTX_set_options(turn_params.tls_ctx, SSL_OP_NO_TLSv1_1);
    }
#if TLSv1_2_SUPPORTED
    if (turn_params.no_tlsv1_2) {
      SSL_CTX_set_options(turn_params.tls_ctx, SSL_OP_NO_TLSv1_2);
    }
#endif
#endif
#else // OPENSSL_VERSION_NUMBER < 0x10100000L
    set_ctx(&turn_params.tls_ctx, "TLS", TLS_server_method());
    if (turn_params.no_tlsv1) {
      SSL_CTX_set_min_proto_version(turn_params.tls_ctx, TLS1_1_VERSION);
    }
    if (turn_params.no_tlsv1_1) {
      SSL_CTX_set_min_proto_version(turn_params.tls_ctx, TLS1_2_VERSION);
    }
#if TLSv1_3_SUPPORTED
    if (turn_params.no_tlsv1_2) {
      SSL_CTX_set_min_proto_version(turn_params.tls_ctx, TLS1_3_VERSION);
    }
#endif
#endif // OPENSSL_VERSION_NUMBER < 0x10100000L
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "TLS cipher suite: %s\n", turn_params.cipher_list);
  }

  if (!turn_params.no_dtls) {
#if !DTLS_SUPPORTED
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "ERROR: DTLS is not supported.\n");
#elif OPENSSL_VERSION_NUMBER < 0x10000000L
    TURN_LOG_FUNC(
        TURN_LOG_LEVEL_WARNING,
        "WARNING: TURN Server was compiled with rather old OpenSSL version, DTLS may not be working correctly.\n");
#else
#if OPENSSL_VERSION_NUMBER < 0x10100000L // before openssl-1.1.0 no version independent API
#if DTLSv1_2_SUPPORTED
    set_ctx(&turn_params.dtls_ctx, "DTLS", DTLSv1_2_server_method()); // openssl-1.0.2
    if (turn_params.no_tlsv1_2) {
      SSL_CTX_set_options(turn_params.dtls_ctx, SSL_OP_NO_DTLSv1_2);
    }
#else
    set_ctx(&turn_params.dtls_ctx, "DTLS", DTLSv1_server_method()); // < openssl-1.0.2
#endif
    if (turn_params.no_tlsv1 || turn_params.no_tlsv1_1) {
      SSL_CTX_set_options(turn_params.dtls_ctx, SSL_OP_NO_DTLSv1);
    }
#else  // OPENSSL_VERSION_NUMBER < 0x10100000L
    set_ctx(&turn_params.dtls_ctx, "DTLS", DTLS_server_method());
    if (turn_params.no_tlsv1 || turn_params.no_tlsv1_1) {
      SSL_CTX_set_min_proto_version(turn_params.dtls_ctx, DTLS1_2_VERSION);
    }
    if (turn_params.no_tlsv1_2) {
      SSL_CTX_set_max_proto_version(turn_params.dtls_ctx, DTLS1_VERSION);
    }
#endif // OPENSSL_VERSION_NUMBER < 0x10100000L
    setup_dtls_callbacks(turn_params.dtls_ctx);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "DTLS cipher suite: %s\n", turn_params.cipher_list);
#endif
  }
  TURN_MUTEX_UNLOCK(&turn_params.tls_mutex);
}

static void reload_ssl_certs(evutil_socket_t sock, short events, void *args) {
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Reloading TLS certificates and keys\n");
  openssl_load_certificates();
  if (turn_params.tls_ctx_update_ev != NULL)
    event_active(turn_params.tls_ctx_update_ev, EV_READ, 0);

  UNUSED_ARG(sock);
  UNUSED_ARG(events);
  UNUSED_ARG(args);
}

static void shutdown_handler(evutil_socket_t sock, short events, void *args) {
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Terminating on signal %d\n", sock);
  turn_params.stop_turn_server = 1;

  UNUSED_ARG(events);
  UNUSED_ARG(args);
}

///////////////////////////////
