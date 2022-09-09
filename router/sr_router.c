/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
// include bool
#include <stdbool.h>
// include malloc
#include <stdlib.h>
// include memset
#include <string.h>
// difftime
#include <time.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
struct node root = {{NULL, NULL}, NULL};
bool tree_exist = false;

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* TODO: FILL IN YOUR CODE HERE */

  // construct trie if does not exist
  if (!tree_exist) {
    // loop through routing table
    struct sr_rt* rt_pointer = sr->routing_table;
    while (rt_pointer) {
      // count number of 1s in the mask
      uint32_t mask_container  = rt_pointer->mask.s_addr;
      int count = 0;
      while (mask_container) {
        mask_container = mask_container & (mask_container - 1);
        count++;
      }
      // if count is 0, that is a default entry
      if (count == 0) {
        printf("no count\n");
        // if root already has child pointers initialized
        if (root.children[0]) {
          printf("1\n");
          (root.children[0])->termination = rt_pointer;
        }
        // if root hasn't initialized child pointers
        else {
          printf("2\n");
          root.children[0] = (struct node*)malloc(sizeof(struct node));
          memset(root.children[0], 0, sizeof(struct node));
          (root.children[0])->termination = rt_pointer;
        }

        // if root already has child pointers initialized
        if (root.children[1]) {
          printf("3\n");
          (root.children[1])->termination = rt_pointer;
        }
        // if root hasn't initialized child pointers
        else {
          printf("4\n");
          root.children[1] = (struct node*)malloc(sizeof(struct node));
          memset(root.children[1], 0, sizeof(struct node));
          (root.children[1])->termination = rt_pointer;
        }
      }
      // if count is not 0, then it is not a default entry
      else {
        uint32_t prefix_container = rt_pointer->dest.s_addr;
        struct node* cur_node = &root;
        for (int i = 31; i > -1; i--) {
          // if the left most bit is 1
          if((prefix_container>>i) & 1) {
            // first check if child exist
            if (!cur_node->children[1]) {
              // create the child node
              cur_node->children[1] = (struct node*)malloc(sizeof(struct node));
              memset(cur_node->children[1], 0, sizeof(struct node));
            }

            // if that's the last bit of prefix, set termination for child node
            if (i == 0) {
              (cur_node->children[1])->termination = rt_pointer;
            }
            cur_node = cur_node->children[1];
          }
          // else the left most bit is 0
          else {
            // first check if child exist
            if (!cur_node->children[0]) {
              // create the child node
              cur_node->children[0] = (struct node*)malloc(sizeof(struct node));
              memset(cur_node->children[0], 0, sizeof(struct node));
            }

            // if that's the last bit of prefix, set termination for child node
            if (i == 0) {
              (cur_node->children[0])->termination = rt_pointer;
            }
            cur_node = cur_node->children[0];
          }


        }
      }
      rt_pointer = rt_pointer->next;
    }
    tree_exist = true;
  }


  // move the ethernet packet header part to the struct
  sr_ethernet_hdr_t* temp_ether_hdr = (sr_ethernet_hdr_t *)(packet);

  enum sr_ethertype arp_type;
  arp_type = ethertype_arp;
  enum sr_ethertype ip_type;
  ip_type = ethertype_ip;

  // branch based on ethertype 1.ip, 2.arp
  printf("before iptype branch\n");
  printf("%d\n", ntohs(temp_ether_hdr->ether_type));
  printf("%d\n", ip_type);
  if (ntohs(temp_ether_hdr->ether_type) == ip_type) {
    printf("inside iptype branch\n");
    // extract ip address from the frame
    print_hdr_ip(packet+14);
    sr_ip_hdr_t* temp_ip_hdr = (sr_ip_hdr_t*)(packet + 14);
    uint32_t ip_container = temp_ip_hdr->ip_dst;

    // if the destination matches the router
    struct sr_if* if_head = sr->if_list;
    bool matched = false;
    while (if_head) {
      if (if_head->ip == temp_ip_hdr->ip_dst) {
        matched = true;
        break;
      }
      if_head = if_head->next;
    }
    if (matched) {
      printf("ip packet to the router\n");
      // checksum
      uint16_t og_ip_sum = temp_ip_hdr->ip_sum;
      temp_ip_hdr->ip_sum = 0;
      if (cksum(temp_ip_hdr, temp_ip_hdr->ip_hl * 4) == og_ip_sum) {
        // if icmp packet
        if (temp_ip_hdr->ip_p == ip_protocol_icmp) {
          sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) (packet + 14 + sizeof(sr_ip_hdr_t));
          printf("icmp header received:\n");
          print_hdr_icmp(icmp_hdr);
          if (icmp_hdr->icmp_type == 8) {
            // checksum
            int icmp_msg_len = ntohs(temp_ip_hdr->ip_len) - temp_ip_hdr->ip_hl * 4;
            uint16_t og_icmp_sum = icmp_hdr->icmp_sum;
            icmp_hdr->icmp_sum = 0;
            printf("icmp sum calculated: %d\n", cksum(icmp_hdr, icmp_msg_len));
            if (cksum(icmp_hdr, icmp_msg_len) == og_icmp_sum) {
              uint8_t* response_packet_p = (uint8_t*) malloc(14 + sizeof(struct sr_ip_hdr) + icmp_msg_len);
              memset(response_packet_p, 0, 14 + sizeof(struct sr_ip_hdr) + icmp_msg_len);
              // fill in ether header
              sr_ethernet_hdr_t* re_ether_hdr = (sr_ethernet_hdr_t*) (response_packet_p);
              memcpy(re_ether_hdr->ether_dhost, temp_ether_hdr->ether_shost, 6);
              memcpy(re_ether_hdr->ether_shost, temp_ether_hdr->ether_dhost, 6);
              re_ether_hdr->ether_type = htons(ethertype_ip);
              printf("icmp echo reply ether header:\n");
              print_hdr_eth(re_ether_hdr);
              // fill in ip header
              sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t*) (response_packet_p + 14);
              reply_ip_hdr->ip_hl = 5;
              reply_ip_hdr->ip_v = 4;
              reply_ip_hdr->ip_tos = 0;
              reply_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + icmp_msg_len);
              reply_ip_hdr->ip_id = htons(0);
              reply_ip_hdr->ip_off = htons(IP_DF);
              reply_ip_hdr->ip_ttl = 64;
              enum sr_ip_protocol icmp_type;
              icmp_type = ip_protocol_icmp;
              reply_ip_hdr->ip_p = icmp_type;
              reply_ip_hdr->ip_src = temp_ip_hdr->ip_dst;
              reply_ip_hdr->ip_dst = temp_ip_hdr->ip_src;
              printf("icmp echo reply ip header:\n");
              print_hdr_ip(reply_ip_hdr);

              // fill in icmp message
              sr_icmp_hdr_t* reply_icmp_hdr = (sr_icmp_hdr_t*) (response_packet_p + 14 + sizeof(struct sr_ip_hdr));
              memcpy(reply_icmp_hdr, icmp_hdr, icmp_msg_len);
              reply_icmp_hdr->icmp_type = 0;
              reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, icmp_msg_len);

              // fill check sum of ip header
              reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, 20);
              struct sr_if* cur_if_head = sr->if_list;
              while (cur_if_head) {
                if (memcmp(cur_if_head->addr, temp_ether_hdr->ether_dhost, 6) == 0) {
                  break;
                }
                cur_if_head = cur_if_head->next;
              }
              sr_send_packet(sr, response_packet_p,
                14 + sizeof(struct sr_ip_hdr) + icmp_msg_len,
                cur_if_head->name
              );
              free(response_packet_p);
            }
          }
        }
        // if tcp or udp
        else if (temp_ip_hdr->ip_p == ip_protocol_tcp || temp_ip_hdr->ip_p == ip_protocol_udp) {
          printf("tcp/udp packet for the router: \n");
          uint8_t* response_packet_p = (uint8_t*) malloc(14 + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
          memset(response_packet_p, 0, 14 + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
          // fill in ether header
          sr_ethernet_hdr_t* re_ether_hdr = (sr_ethernet_hdr_t*) (response_packet_p);
          memcpy(re_ether_hdr->ether_dhost, temp_ether_hdr->ether_shost, 6);
          memcpy(re_ether_hdr->ether_shost, temp_ether_hdr->ether_dhost, 6);
          re_ether_hdr->ether_type = htons(ethertype_ip);
          printf("icmp t3c3 ether header:\n");
          print_hdr_eth(re_ether_hdr);
          // fill in ip header
          sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t*) (response_packet_p + 14);
          reply_ip_hdr->ip_hl = 5;
          reply_ip_hdr->ip_v = 4;
          reply_ip_hdr->ip_tos = 0;
          reply_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
          reply_ip_hdr->ip_id = htons(0);
          reply_ip_hdr->ip_off = htons(IP_DF);
          reply_ip_hdr->ip_ttl = 64;
          enum sr_ip_protocol icmp_type;
          icmp_type = ip_protocol_icmp;
          reply_ip_hdr->ip_p = icmp_type;
          struct sr_if* cur_if_head = sr->if_list;
          while (cur_if_head) {
            if (memcmp(cur_if_head->addr, temp_ether_hdr->ether_dhost, 6) == 0) {
              break;
            }
            cur_if_head = cur_if_head->next;
          }
          reply_ip_hdr->ip_src = cur_if_head->ip;
          reply_ip_hdr->ip_dst = temp_ip_hdr->ip_src;
          printf("icmp t3c3 ip header:\n");
          print_hdr_ip(reply_ip_hdr);

          // fill in icmp message
          sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t*) (response_packet_p + 14 + sizeof(struct sr_ip_hdr));
          reply_icmp_hdr->icmp_type = 3;
          reply_icmp_hdr->icmp_code = 3;
          memcpy(reply_icmp_hdr->data, temp_ip_hdr, sizeof(struct sr_ip_hdr));
          memcpy(reply_icmp_hdr->data + 20, packet + 14 + sizeof(struct sr_ip_hdr), 8);
          reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(struct sr_icmp_t3_hdr));

          // fill check sum of ip header
          reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, 20);
          sr_send_packet(sr, response_packet_p,
            14 + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr),
            cur_if_head->name
          );
          free(response_packet_p);
        }
      }
    }
    // if destination does not match the router
    else {
      printf("forwarding\n");
      // checksum
      uint16_t og_ip_sum = temp_ip_hdr->ip_sum;
      temp_ip_hdr->ip_sum = 0;
      printf("calculated ip sum: %d\n", cksum(temp_ip_hdr, temp_ip_hdr->ip_hl * 4));
      if (cksum(temp_ip_hdr, temp_ip_hdr->ip_hl * 4) == og_ip_sum) {
        printf("checksum matched\n");
        // decrement ttl
        temp_ip_hdr->ip_ttl -= 1;
        if (temp_ip_hdr->ip_ttl == 0) {
          printf("ttl = 0\n");
          uint8_t* response_packet_p = (uint8_t*) malloc(14 + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
          memset(response_packet_p, 0, 14 + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
          // fill in ether header
          sr_ethernet_hdr_t* re_ether_hdr = (sr_ethernet_hdr_t*) (response_packet_p);
          memcpy(re_ether_hdr->ether_dhost, temp_ether_hdr->ether_shost, 6);
          memcpy(re_ether_hdr->ether_shost, temp_ether_hdr->ether_dhost, 6);
          re_ether_hdr->ether_type = htons(ethertype_ip);
          printf("icmp t11 ether header:\n");
          print_hdr_eth(re_ether_hdr);
          // fill in ip header
          sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t*) (response_packet_p + 14);
          reply_ip_hdr->ip_hl = 5;
          reply_ip_hdr->ip_v = 4;
          reply_ip_hdr->ip_tos = 0;
          reply_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
          reply_ip_hdr->ip_id = htons(0);
          reply_ip_hdr->ip_off = htons(IP_DF);
          reply_ip_hdr->ip_ttl = 64;
          enum sr_ip_protocol icmp_type;
          icmp_type = ip_protocol_icmp;
          reply_ip_hdr->ip_p = icmp_type;
          struct sr_if* cur_if_head = sr->if_list;
          while (cur_if_head) {
            if (memcmp(cur_if_head->addr, temp_ether_hdr->ether_dhost, 6) == 0) {
              break;
            }
            cur_if_head = cur_if_head->next;
          }
          reply_ip_hdr->ip_src = cur_if_head->ip;
          reply_ip_hdr->ip_dst = temp_ip_hdr->ip_src;
          printf("icmp t11 ip header:\n");
          print_hdr_ip(reply_ip_hdr);

          // fill in icmp message
          sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t*) (response_packet_p + 14 + sizeof(struct sr_ip_hdr));
          reply_icmp_hdr->icmp_type = 11;
          reply_icmp_hdr->icmp_code = 0;
          memcpy(reply_icmp_hdr->data, temp_ip_hdr, sizeof(struct sr_ip_hdr));
          memcpy(reply_icmp_hdr->data + 20, packet + 14 + sizeof(struct sr_ip_hdr), 8);
          reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(struct sr_icmp_t3_hdr));
          printf("here\n");
          // fill check sum of ip header
          reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, 20);
          sr_send_packet(sr, response_packet_p,
            14 + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr),
            cur_if_head->name
          );
          printf("here2\n");
          free(response_packet_p);
        }
        else {
          // recompute checksum
          temp_ip_hdr->ip_sum = cksum(temp_ip_hdr, temp_ip_hdr->ip_hl * 4);
          // check next hop ip
          struct node* cur_node = &root;
          struct sr_rt* longest_matched_rt = longest_matching_prefix(ip_container, cur_node);
          if (longest_matched_rt) {
            uint32_t next_hop_ip = longest_matched_rt->gw.s_addr;
            struct sr_arpentry* lookup_res = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
            if (lookup_res) {
              printf("in cache\n");
              memcpy(temp_ether_hdr->ether_dhost, lookup_res->mac, 6);
              struct sr_if* next_hop_if = sr_get_interface(sr, longest_matched_rt->interface);
              memcpy(temp_ether_hdr->ether_shost, next_hop_if->addr, 6);
              sr_send_packet(sr, packet, len, longest_matched_rt->interface);
              printf("free1\n");
              free(lookup_res);
            }
            else {
              printf("not in cache\n");
              // get interface where the packet comes from
              struct sr_arpreq* req = sr_arpcache_queuereq(
                &(sr->cache),
                next_hop_ip,
                packet,
                len,
                longest_matched_rt->interface
              );
              handle_arpreq(req, sr);
            }
          }
          else {
            printf("no matching entry in routing table to foward\n");
            uint8_t* response_packet_p = (uint8_t*) malloc(14 + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
            memset(response_packet_p, 0, 14 + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
            // fill in ether header
            sr_ethernet_hdr_t* re_ether_hdr = (sr_ethernet_hdr_t*) (response_packet_p);
            memcpy(re_ether_hdr->ether_dhost, temp_ether_hdr->ether_shost, 6);
            memcpy(re_ether_hdr->ether_shost, temp_ether_hdr->ether_dhost, 6);
            re_ether_hdr->ether_type = htons(ethertype_ip);
            printf("icmp t3c0 ether header:\n");
            print_hdr_eth(re_ether_hdr);
            // fill in ip header
            sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t*) (response_packet_p + 14);
            reply_ip_hdr->ip_hl = 5;
            reply_ip_hdr->ip_v = 4;
            reply_ip_hdr->ip_tos = 0;
            reply_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr));
            reply_ip_hdr->ip_id = htons(0);
            reply_ip_hdr->ip_off = htons(IP_DF);
            reply_ip_hdr->ip_ttl = 64;
            enum sr_ip_protocol icmp_type;
            icmp_type = ip_protocol_icmp;
            reply_ip_hdr->ip_p = icmp_type;
            struct sr_if* cur_if_head = sr->if_list;
            while (cur_if_head) {
              if (memcmp(cur_if_head->addr, temp_ether_hdr->ether_dhost, 6) == 0) {
                break;
              }
              cur_if_head = cur_if_head->next;
            }
            reply_ip_hdr->ip_src = cur_if_head->ip;
            reply_ip_hdr->ip_dst = temp_ip_hdr->ip_src;
            printf("icmp t3c0 ip header:\n");
            print_hdr_ip(reply_ip_hdr);

            // fill in icmp message
            sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t*) (response_packet_p + 14 + sizeof(struct sr_ip_hdr));
            reply_icmp_hdr->icmp_type = 3;
            memcpy(reply_icmp_hdr->data, temp_ip_hdr, sizeof(struct sr_ip_hdr));
            memcpy(reply_icmp_hdr->data + 20, packet + 14 + sizeof(struct sr_ip_hdr), 8);
            reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(struct sr_icmp_t3_hdr));

            // fill check sum of ip header
            reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, 20);
            sr_send_packet(sr, response_packet_p,
              14 + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr),
              cur_if_head->name
            );
            free(response_packet_p);
          }
        }
      }
    }
  }

  else if (ntohs(temp_ether_hdr->ether_type) == arp_type) {
    printf("inside arptype branch\n");
    print_hdr_arp(packet+14);
    sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet+14);

    enum sr_arp_opcode request_type;
    request_type = arp_op_request;
    enum sr_arp_opcode reply_type;
    reply_type = arp_op_reply;

    // process reply
    if (ntohs(arphdr->ar_op) == arp_op_reply) {
      printf("inside process reply branch\n");
      struct sr_arpreq* req_in_queue = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, arphdr->ar_sip);
      if (req_in_queue) {
        struct sr_packet* cur_packet = req_in_queue->packets;
        while (cur_packet) {
          sr_ethernet_hdr_t* cur_packet_ether_hdr = (sr_ethernet_hdr_t*) cur_packet->buf;
          memcpy(cur_packet_ether_hdr->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);
          struct sr_if* outgoing_if = sr_get_interface(sr, cur_packet->iface);
          memcpy(cur_packet_ether_hdr->ether_shost, outgoing_if->addr, 6);
          sr_send_packet(sr, cur_packet->buf, cur_packet->len, cur_packet->iface);

          cur_packet = cur_packet->next;
        }
        sr_arpreq_destroy(&(sr->cache), req_in_queue);
      }
    }
    // process request
    else if (ntohs(arphdr->ar_op) == arp_op_request){
      printf("inside process request branch\n");
      // if destination ip is one of the router's interface
      struct sr_if* if_head = sr->if_list;
      bool matched = false;
      while (if_head) {
        if (if_head->ip == arphdr->ar_tip) {
          matched = true;
          break;
        }
        if_head = if_head->next;
      }
      if (matched) {
        printf("interface matched in arp request\n");
        struct sr_if* cur_if = if_head;

        uint8_t* response_packet_p = (uint8_t*) malloc(42);
        // fill out the ethernet header
        sr_ethernet_hdr_t* reply_ether_hdr = (sr_ethernet_hdr_t*) (response_packet_p);
        memcpy(reply_ether_hdr->ether_dhost, arphdr->ar_sha, 6);
        memcpy(reply_ether_hdr->ether_shost, cur_if->addr, 6);
        reply_ether_hdr->ether_type = htons(arp_type);
        print_hdr_eth(response_packet_p);


        // fill out the arp header
        enum sr_arp_hrd_fmt hrd_fmt;
        hrd_fmt = arp_hrd_ethernet;

        sr_arp_hdr_t* reply = (sr_arp_hdr_t*) (response_packet_p+14);
        reply->ar_hrd = htons(hrd_fmt);
        reply->ar_pro = htons(ip_type);
        reply->ar_hln = 6;
        reply->ar_pln = 4;
        reply->ar_op = htons(arp_op_reply);
        memcpy(reply->ar_sha, cur_if->addr, 6);
        reply->ar_sip = cur_if->ip;
        memcpy(reply->ar_tha, arphdr->ar_sha, 6);
        reply->ar_tip = arphdr->ar_sip;
        printf("filled arp response: \n");
        print_hdr_arp(response_packet_p+14);

        sr_send_packet(sr, response_packet_p, 42, cur_if->name);
        printf("free2\n");
        free(response_packet_p);
      }
    }
  }
}/* end sr_ForwardPacket */

struct sr_rt* longest_matching_prefix(uint32_t ip_container, struct node* cur_node) {
  // current number of bits matched
  int cur_depth = 0;
  int longest_matched_depth = 0;
  // current longest matched table entry
  struct sr_rt* longest_matched_rt = NULL;
  // do longest prefix matching
  for (int i = 31; i > -1; i--) {
    if ((ip_container>>i)&1) {
      // if node does not exist in trie, break
      if (!cur_node->children[1]) {
        break;
      }
      else {
        cur_node = cur_node->children[1];
        if (cur_node->termination && cur_depth >= longest_matched_depth) {
          longest_matched_depth = cur_depth;
          longest_matched_rt = cur_node->termination;
        }
      }
    }
    else {
      // if node does not exist in trie, break
      if (!cur_node->children[0]) {
        break;
      }
      else {
        cur_node = cur_node->children[0];
        if (cur_node->termination && cur_depth >= longest_matched_depth) {
          longest_matched_depth = cur_depth;
          longest_matched_rt = cur_node->termination;
        }
      }
    }
  }
  if (longest_matched_rt) {
    printf("%s\n", "matched prefix: ");
    printf("%s\n", longest_matched_rt->interface);
  }
  else {
    printf("no match\n");
  }

  return longest_matched_rt;
}

void handle_arpreq(struct sr_arpreq* req, struct sr_instance* sr) {
  time_t current;
  time(&current);
  printf("difftime: %f\n", difftime(current, req->sent));
  if (difftime(current, req->sent) >= 1.0) {
    if (req->times_sent >= 7) {
      // send icmp host unreachable to source addr of all pkts waiting on this request
      struct sr_packet* cur_packet = req->packets;
      while (cur_packet) {
        size_t total_frame_len = 14 + sizeof(sr_ip_hdr_t) + sizeof(struct sr_icmp_t3_hdr);
        uint8_t* response_packet_p = (uint8_t*) malloc(total_frame_len);
        memset(response_packet_p, 0, total_frame_len);
        // fill out the ethernet header
        sr_ethernet_hdr_t* reply_ether_hdr = (sr_ethernet_hdr_t*) (response_packet_p);
        sr_ethernet_hdr_t* packet_buf_ether_hdr = (sr_ethernet_hdr_t*) (cur_packet->buf);
        memcpy(reply_ether_hdr->ether_dhost, packet_buf_ether_hdr->ether_shost, 6);
        struct sr_if* cur_if_head = sr->if_list;
        while (cur_if_head) {
          if (memcmp(cur_if_head->addr, packet_buf_ether_hdr->ether_dhost, 6) == 0) {
            break;
          }
          cur_if_head = cur_if_head->next;
        }
        memcpy(reply_ether_hdr->ether_shost, cur_if_head->addr, 6);

        enum sr_ethertype ip_type;
        ip_type = ethertype_ip;
        reply_ether_hdr->ether_type = htons(ip_type);
        printf("handle_arpreq icmp unreachable ether hdr: \n");
        print_hdr_eth(response_packet_p);

        // fill out the ip header
        struct sr_ip_hdr* reply_ip_hdr = (struct sr_ip_hdr*) (response_packet_p + 14);
        reply_ip_hdr->ip_hl = 5;
        reply_ip_hdr->ip_v = 4;
        reply_ip_hdr->ip_tos = 0;
        reply_ip_hdr->ip_len = htons(total_frame_len - 14);
        reply_ip_hdr->ip_id = htons(0);
        reply_ip_hdr->ip_off = htons(IP_DF);
        reply_ip_hdr->ip_ttl = 64;
        enum sr_ip_protocol icmp_type;
        icmp_type = ip_protocol_icmp;
        reply_ip_hdr->ip_p = icmp_type;
        reply_ip_hdr->ip_src = cur_if_head->ip;
        sr_ip_hdr_t* packet_buf_ip_hdr = (sr_ip_hdr_t*) ((cur_packet->buf)+14);
        reply_ip_hdr->ip_dst = packet_buf_ip_hdr->ip_src;
        printf("handle_arpreq icmp unreachable ip hdr: \n");
        print_hdr_ip(reply_ip_hdr);

        // fill out icmp header
        sr_icmp_t3_hdr_t* reply_icmp_hdr = (sr_icmp_t3_hdr_t*) (response_packet_p + 14 + sizeof(sr_ip_hdr_t));
        reply_icmp_hdr->icmp_type = 3;
        reply_icmp_hdr->icmp_code = 1;
        memcpy(reply_icmp_hdr->data, cur_packet->buf + 14, sizeof(struct sr_ip_hdr));
        memcpy(reply_icmp_hdr->data + 20, cur_packet->buf + 14 + sizeof(struct sr_ip_hdr), 8);
        reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(struct sr_icmp_t3_hdr));
        printf("handle_arpreq icmp unreachable icmp hdr: \n");
        print_hdr_icmp(reply_icmp_hdr);

        reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, 20);

        sr_send_packet(sr, response_packet_p, total_frame_len, cur_if_head->name);
        printf("free3\n");
        free(response_packet_p);
        cur_packet = cur_packet->next;
      }
      sr_arpreq_destroy(&(sr->cache), req);
    }
    else {
      // send arp request
      uint8_t* request_packet_p = (uint8_t*) malloc(42);
      // fill out the ethernet header
      sr_ethernet_hdr_t* request_ether_hdr = (sr_ethernet_hdr_t*) (request_packet_p);
      memset(request_ether_hdr->ether_dhost, 0, 6);
      uint8_t broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
      uint32_t destination_ip_container = req->ip;
      struct node* cur_node = &root;
      struct sr_rt* longest_matched_rt = longest_matching_prefix(destination_ip_container, cur_node);
      struct sr_if* destination_if = sr_get_interface(sr, longest_matched_rt->interface);
      memcpy(request_ether_hdr->ether_dhost, broadcast_addr, 6);
      memcpy(request_ether_hdr->ether_shost, destination_if->addr, 6);
      enum sr_ethertype arp_type;
      arp_type = ethertype_arp;
      request_ether_hdr->ether_type = htons(arp_type);
      printf("handle_arpreq arp req ether hdr: \n");
      print_hdr_eth(request_packet_p);

      // fill out the arp header
      enum sr_arp_hrd_fmt hrd_fmt;
      hrd_fmt = arp_hrd_ethernet;
      enum sr_arp_opcode request_type;
      request_type = arp_op_request;
      enum sr_ethertype ip_type;
      ip_type = ethertype_ip;
      sr_arp_hdr_t* request_arp_hdr = (sr_arp_hdr_t*) (request_packet_p + 14);
      request_arp_hdr->ar_hrd = htons(hrd_fmt);
      request_arp_hdr->ar_pro = htons(ip_type);
      request_arp_hdr->ar_hln = 6;
      request_arp_hdr->ar_pln = 4;
      request_arp_hdr->ar_op = htons(arp_op_request);
      memcpy(request_arp_hdr->ar_sha, destination_if->addr, 6);
      request_arp_hdr->ar_sip = destination_if->ip;
      memset(request_arp_hdr->ar_tha, 0, 6);
      request_arp_hdr->ar_tip = req->ip;
      printf("handle_arpreq arp req arp hdr: \n");
      print_hdr_arp(request_packet_p+14);

      sr_send_packet(sr, request_packet_p, 42, destination_if->name);

      time_t current;
      time(&current);
      req->sent = current;
      req->times_sent++;
      printf("free4\n");
      free(request_packet_p);
    }
  }
}
