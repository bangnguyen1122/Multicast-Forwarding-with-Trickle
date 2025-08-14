#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include <string.h>
#include <stdlib.h>
#include "net/ip/uip.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"
#include "net/rpl/rpl.h"

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001

#define I_MIN (CLOCK_SECOND * 4)
#define I_MAX (CLOCK_SECOND * 64)
#define K 1

static struct uip_udp_conn *mcast_conn;
static char buf[MAX_PAYLOAD_LEN];

static clock_time_t I = I_MIN;
static clock_time_t t;
static struct etimer trickle_etimer, wait_etimer;
static uint8_t c = 0;

static uint32_t seq_id = 1;
static uint32_t last_recv_id = 0; /* last id received (for consistency checking) */

PROCESS(rpl_root_process, "RPL ROOT with Trickle Multicast");
AUTOSTART_PROCESSES(&rpl_root_process);

/* Safe memcpy-based read of 32-bit id in network byte order */
static uint32_t read_net32_from_appdata(void) {
  uint32_t x_net = 0;
  memcpy(&x_net, uip_appdata, sizeof(x_net));
  return uip_ntohl(x_net);
}

static void multicast_send(void) {
  uint32_t id_host;
  uint32_t id_net;

  memset(buf, 0, MAX_PAYLOAD_LEN);

  /* randomly sometimes send a duplicate to exercise Trickle behavior */
  if(random_rand() % 2 == 0 && seq_id > 1) {
    id_host = seq_id - 1;
    PRINTF("Send duplicated packet\n");
  } else {
    id_host = seq_id;
    PRINTF("Send new packet\n");
    seq_id++;
  }

  id_net = uip_htonl(id_host);
  memcpy(buf, &id_net, sizeof(id_net));

  PRINTF("Send to: ");
  PRINT6ADDR(&mcast_conn->ripaddr);
  PRINTF(" Port %u,", uip_ntohs(mcast_conn->rport));
  PRINTF(" (msg=0x%08lx)", (unsigned long)id_host);
  PRINTF(" %lu bytes\n", (unsigned long)sizeof(id_net));

  uip_udp_packet_send(mcast_conn, buf, sizeof(id_net));
}

static void prepare_mcast(void) {
  uip_ipaddr_t ipaddr;
  uip_ip6addr(&ipaddr, 0xFF1E, 0, 0, 0, 0, 0, 0x89, 0xABCD);
  mcast_conn = udp_new(&ipaddr, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
  if(mcast_conn == NULL) {
    PRINTF("ERROR: udp_new returned NULL\n");
  }
}

static void set_own_addresses(void) {
  int i;
  uint8_t state;
  rpl_dag_t *dag;
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  PRINTF("Our IPv6 addresses:\n");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      if(state == ADDR_TENTATIVE) {
        uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }

  dag = rpl_set_root(RPL_DEFAULT_INSTANCE, &ipaddr);
  if(dag != NULL) {
    rpl_set_prefix(dag, &ipaddr, 64);
    PRINTF("Created a new RPL dag with ID: ");
    PRINT6ADDR(&dag->dag_id);
    PRINTF("\n");
  }
}

/* Handle incoming packets (Trickle consistency checks)
   - If recv_id == last_recv_id => consistent -> c++
   - Else => inconsistent -> reset I to I_MIN (if > I_MIN) and restart timers
*/
static void tcpip_handler(void) {
  if(uip_newdata()) {
    uint32_t recv_id = read_net32_from_appdata();

    /* print basic receive line similar to sink */
    PRINTF("In: [0x%08lx], TTL %u\n", (unsigned long)recv_id, UIP_IP_BUF->ttl);

    if(recv_id == last_recv_id) {
      c++;
      PRINTF("Consistent seen: recv_id=0x%08lx, c=%u\n", (unsigned long)recv_id, c);
    } else {
      PRINTF("Inconsistent seen: recv_id=0x%08lx (was 0x%08lx). Resetting I->I_MIN\n",
             (unsigned long)recv_id, (unsigned long)last_recv_id);
      last_recv_id = recv_id;
      if(I > I_MIN) {
        I = I_MIN;
        t = I / 2 + (random_rand() % (I / 2));
        etimer_set(&trickle_etimer, I);
        etimer_set(&wait_etimer, t);
        c = 0;
        PRINTF("Set new interval I = %lu, t = %lu, c = %u\n",
               (unsigned long)I, (unsigned long)t, c);
        PRINTF("Wait new packet...\n");
      }
    }
  }
}

PROCESS_THREAD(rpl_root_process, ev, data) {
  PROCESS_BEGIN();

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);
  NETSTACK_MAC.off(1);

  set_own_addresses();
  prepare_mcast();

  /* Initialize Trickle parameters */
  I = I_MIN;
  t = I / 2 + (random_rand() % (I / 2));
  etimer_set(&trickle_etimer, I);

  PRINTF("Wait new packet...\n");

  etimer_set(&wait_etimer, t);

  PRINTF("Set new interval I = %lu, t = %lu, c = %u\n", (unsigned long)I, (unsigned long)t, c);

  c = 0;

  while(1) {
    PROCESS_YIELD();

    if(ev == tcpip_event) {
      tcpip_handler();
    }

    if(etimer_expired(&wait_etimer)) {
      PRINTF("At t: checking c=%u (K=%u)\n", c, K);
      if(c < K) {
        multicast_send();
      } else {
        PRINTF("c (%u) >= K (%u) -> suppress transmit (refresh only)\n", c, K);
      }
    }

    if(etimer_expired(&trickle_etimer)) {
      I = (I * 2 > I_MAX) ? I_MAX : I * 2;
      t = I / 2 + (random_rand() % (I / 2));
      etimer_set(&trickle_etimer, I);
      etimer_set(&wait_etimer, t);
      c = 0;
      PRINTF("Interval tick: I=%lu, next t=%lu, reset c=0\n", (unsigned long)I, (unsigned long)t);
      PRINTF("Wait new packet...\n");
    }

  }

  PROCESS_END();
}
