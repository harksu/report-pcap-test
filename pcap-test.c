#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


void print_mac_addr(struct libnet_ethernet_hdr* mac_hdr, const char* field){

	printf("%s:",field);
	if(field =="src_mac_addr"){
		for (int i = 0; i<ETHER_ADDR_LEN; i++){
			i == ETHER_ADDR_LEN-1 ? printf("%02x\n",mac_hdr->ether_shost[i]) : printf("%02x:",mac_hdr->ether_shost[i]);
		}
	}
	else if(field =="dst_mac_addr"){

		for (int i = 0; i<ETHER_ADDR_LEN; i++){
			i == ETHER_ADDR_LEN-1 ? printf("%02x\n",mac_hdr->ether_dhost[i]) : printf("%02x:",mac_hdr->ether_dhost[i]);
		}
	}
	else{
		printf("field is src_mac_addr or dst_mac_addr, try again");
		return;
	}
}

void print_ip_addr(struct libnet_ipv4_hdr* ipv4_hdr){
	u_int8_t ip1=0, ip2=0, ip3=0, ip4=0;
	u_int32_t src_ip_addr = src_ip_addr = ntohl(ipv4_hdr->ip_src.s_addr);
	u_int32_t dst_ip_addr = ntohl(ipv4_hdr->ip_dst.s_addr);



	ip1 = (src_ip_addr && 0xff000000) >> 24;
	ip2 = (src_ip_addr && 0x00ff0000) >> 16;
	ip3 = (src_ip_addr && 0x0000ff00) >> 8;
	ip4 = (src_ip_addr && 0xff000000);
	printf("ipv4_src_address: %d.%d.%d.%d\n",ip1,ip2,ip3,ip4);

	ip1 = (dst_ip_addr && 0xff000000) >> 24;
	ip2 = (dst_ip_addr && 0x00ff0000) >> 16;
	ip3 = (dst_ip_addr && 0x0000ff00) >> 8;
	ip4 = (dst_ip_addr && 0xff000000);
	printf("ipv4_dst_address: %d.%d.%d.%d\n",ip1,ip2,ip3,ip4);

	//refactoring,, 
}


void print_payload(const u_char* payload, int len) {
	printf("Payload: ");
	for (int i = 0; i < len && i < 20; i++) {
		printf("%02x ", payload[i]);
	}
	printf("\n");
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;

		struct libnet_ethernet_hdr* eth_hdr; //ethernet header
		struct libnet_ipv4_hdr* ipv4_hdr; // ipv4 header
		struct libnet_tcp_hdr* tcp_hdr; // tcp header 

		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		eth_hdr = (struct libnet_ethernet_hdr*)packet;


		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;
	
		ipv4_hdr = (struct libnet_ipv4_hdr*)(packet+sizeof(*eth_hdr));
		if (ipv4_hdr->ip_p != IPPROTO_TCP) continue;

		tcp_hdr = (struct libnet_tcp_hdr*)(packet+sizeof(*eth_hdr)+sizeof(*ipv4_hdr));
		print_mac_addr(eth_hdr, "src_mac_addr");
		print_mac_addr(eth_hdr, "dst_mac_addr");
		print_ip_addr(ipv4_hdr);
		printf("tcp_src_port: %u\ntcp_dst_port: %u\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));

		const u_char* payload = packet + sizeof(*eth_hdr) + sizeof(*ipv4_hdr) + sizeof(*tcp_hdr);
		int payload_len = (header->caplen) - (sizeof(*eth_hdr) + sizeof(*ipv4_hdr) + sizeof(*tcp_hdr));
		print_payload(payload, payload_len);
	}
	pcap_close(pcap);
	return 0;
}

