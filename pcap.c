#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
    printf("syntax: pcap <interface>\n");
    printf("sample: pcap wlan0\n");
}

void packet_processor(const struct pcap_pkthdr* header, const u_char* packet) {

    // Ethernet 프레임의 타입 필드를 검사하여 ARP 패킷인 경우 무시
    if (packet[12] == 0x08 && packet[13] == 0x06) {
        return;
    }

    // 2 계층 정보수집을 위한 Ethernet 헤더 파싱
    u_char* eth_dest = packet;
    u_char* eth_source = packet + 6;

    // 3 계층 정보수집을 위한 IP 헤더 파싱
    u_char* ip_header = packet + 14;
    u_char ip_version = (*ip_header) >> 4;
    u_char ip_header_length = ((*ip_header) & 0x0F);
    u_char* ip_source = ip_header + 12;
    u_char* ip_dest = ip_header + 16;

    // 4 계층 정보수집을 위한 TCP 헤더 파싱
    u_char* tcp_header = ip_header + (ip_header_length * 4);
    u_short tcp_source_port = *((u_short*)tcp_header);
    u_short tcp_dest_port = *((u_short*)(tcp_header + 2));

    // TCP 프로토콜 번호를 확인하여 TCP 패킷인 경우에만 출력
    if (ip_header[9] == 6) {  // TCP 프로토콜 번호 = 6

        // TCP 의 Offset 필드를 이용해 Payload의 시작점을 찾고 패킷 전체길이(header->len)에서 Payload 시작점(payload - packet)을 빼서 길이를 구한다
        u_char* payload = tcp_header + ((tcp_header[12] >> 4) * 4);
        int payload_length = header->len - (payload - packet);

        printf("[2계층] Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_source[0], eth_source[1], eth_source[2], eth_source[3], eth_source[4], eth_source[5],
               eth_dest[0], eth_dest[1], eth_dest[2], eth_dest[3], eth_dest[4], eth_dest[5]);

        printf("[3계층] Src IP: %u.%u.%u.%u, Dst IP: %u.%u.%u.%u\n",
               ip_source[0], ip_source[1], ip_source[2], ip_source[3],
               ip_dest[0], ip_dest[1], ip_dest[2], ip_dest[3]);

        printf("[4계층] Src Port: %d, Dst Port: %d\n", ntohs(tcp_source_port), ntohs(tcp_dest_port));

        printf("Payload (최대 16 byte): ");
        for (int i = 0; i < payload_length && i < 16; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");

        printf("패킷의 전체 길이: %u\n\n", header->len);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
        return 1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        packet_processor(header, packet);
    }

    pcap_close(pcap);
    return 0;
}
