#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

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
		if(tcp_hdr){
			print_mac_addr(eth_hdr, "src_mac_addr");
			print_mac_addr(eth_hdr, "dst_mac_addr");
//		eth_hdr->ether_type && printf("ipv4_header => src_ip: %u dst_ip: %u \n", ipv4_hdr->ip_src, ipv4_hdr->ip_dst);
//		printf("tcp_hedaer => src_port: %u dst_port: %u \n" , tcp_hdr->th_sport,tcp_hdr->th_dport);
		}
	}

	pcap_close(pcap);
}
