#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/rpl/rpl.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define MCAST_SINK_UDP_PORT 3001 /* Host byte order */

static struct uip_udp_conn *sink_conn;
static uint16_t count = 0;
static uint32_t last_id = 0;

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_CONF_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#error "Check the values of: NETSTACK_CONF_WITH_IPV6, UIP_CONF_ROUTER, UIP_CONF_IPV6_RPL"
#endif

PROCESS(mcast_sink_process, "Multicast Sink");
AUTOSTART_PROCESSES(&mcast_sink_process);

static uint32_t read_net32_from_appdata_sink(void) {
  uint32_t x_net = 0;
  memcpy(&x_net, uip_appdata, sizeof(x_net));
  return uip_ntohl(x_net);
}

static void tcpip_handler(void)
{
  if(uip_newdata()) {
    uint32_t recv_id = read_net32_from_appdata_sink();
    count++;

    if(recv_id == last_id) {
      PRINTF("In: [0x%08lx], TTL %u, total %u Packet duplicated\n",
             (unsigned long)recv_id, UIP_IP_BUF->ttl, count);
    } else {
      PRINTF("In: [0x%08lx], TTL %u, total %u\n",
             (unsigned long)recv_id, UIP_IP_BUF->ttl, count);
      last_id = recv_id;
    }
  }
}

static uip_ds6_maddr_t *
join_mcast_group(void)
{
  uip_ipaddr_t addr;
  uip_ds6_maddr_t *rv;

  /* First, set our v6 global */
  uip_ip6addr(&addr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&addr, &uip_lladdr);
  uip_ds6_addr_add(&addr, 0, ADDR_AUTOCONF);

  /* Join multicast group FF1E::89:ABCD */
  uip_ip6addr(&addr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
  rv = uip_ds6_maddr_add(&addr);

  if(rv) {
    PRINTF("Joined multicast group ");
    PRINT6ADDR(&uip_ds6_maddr_lookup(&addr)->ipaddr);
    PRINTF("\n");
  }
  return rv;
}

PROCESS_THREAD(mcast_sink_process, ev, data)
{
  PROCESS_BEGIN();

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);

  if(join_mcast_group() == NULL) {
    PRINTF("Failed to join multicast group\n");
    PROCESS_EXIT();
  }

  if(rpl_get_any_dag() != NULL) {
    PRINTF("Node rank: %u\n", rpl_get_any_dag()->rank);
  } else {
    PRINTF("No DAG found yet.\n");
  }

  count = 0;

  sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  PRINTF("Listening: ");
  PRINT6ADDR(&sink_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
        UIP_HTONS(sink_conn->lport), UIP_HTONS(sink_conn->rport));

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }

  PROCESS_END();
}
