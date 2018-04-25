#include <queue>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/

static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
    register unsigned long sum = 0;
    while (count > 1) {
        sum += * addr++;
        count -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(count > 0) {
        sum += ((*addr)&htons(0xFF00));
    }
    //Fold sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    //one's complement
    sum = ~sum;
    return ((unsigned short)sum);
}

/* set ip checksum of a given ip header*/

void compute_ip_checksum(struct iphdr* iphdrp){
    iphdrp->check = 0;
    iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}

/* set tcp checksum: given IP header and tcp segment */

void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);

    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

/* set udp checksum: given IP header and udp segment */
void compute_udp_checksum(struct iphdr *pIph, unsigned short *ipPayload){
    //to-do
}

int getWindowScale(tcphdr *tcpHdr){
    int position = 20; //tcp header
    int tcpHdrLen = tcpHdr->doff * 4;
    uint8_t kind, length;

    if (tcpHdrLen > 20)
        do{
            kind= ((uint8_t*)tcpHdr)[position];
            if (kind == 0 || kind == 1)
                length = 1;
            else {
                length = ((uint8_t*)tcpHdr)[position + 1];
                if (kind == 3 && length == 3)
                    return ((uint8_t*)tcpHdr)[position + 2];
            }
            position += length;
        }
        while(tcpHdrLen-position >= 3);
    return 0;

}

class VpnConnection {

protected:
    int sd; //Socket Descriptor
    uint8_t protocol; // 17:UDP, 6:TCP

public:
    uint8_t customHeaders[IP_MAXPACKET];
    uint8_t dataReceived[IP_MAXPACKET - 40];
    uint8_t lastPacket[IP_MAXPACKET];
    struct epoll_event ev;

    std::queue<uint8_t*> queue;

    VpnConnection(std::string mKey, int mSd, uint8_t mProtocol) {
        key = mKey;
        sd = mSd;
        protocol = mProtocol;
    }

    uint8_t getProtocol() { return protocol; }
    int getSocket() { return sd; }

    std::string key;
};

class TcpConnection : public VpnConnection {

public:
    uint32_t currAck;
    uint32_t currSeq;
    uint32_t lastAckSent;

    int bytesReceived;
    uint32_t baseSeq;

    uint16_t currPeerWindow;
    uint16_t S_WSS;
    int lastBytesReceived;

    bool connected;

    void changeHeader(struct ip* ipHdr, struct tcphdr* tcpHdr) {

        struct in_addr auxIp = ipHdr->ip_src;
        ipHdr->ip_src = ipHdr->ip_dst;
        ipHdr->ip_dst = auxIp;

        uint16_t auxPort= tcpHdr->source;
        tcpHdr->source = tcpHdr->dest;
        tcpHdr->dest = auxPort;

        tcpHdr->th_off = 5;
    }

    TcpConnection(std::string mKey, int mSd, uint8_t *packet,
                  bool newKey, uint16_t ipHdrLen, uint16_t tcpHdrLen, uint16_t payloadDataLen) : VpnConnection(mKey, mSd, IPPROTO_TCP){
        key = mKey;
        sd = mSd;
        struct tcphdr* tcpHdr = (struct tcphdr*) (packet + ipHdrLen);
        memcpy(customHeaders, packet, ipHdrLen + tcpHdrLen);
        changeHeader((ip *) customHeaders, (tcphdr *) (customHeaders + ipHdrLen));
        baseSeq = 2092188733;
        if(newKey){
            currAck = ntohl(tcpHdr->seq) + 1;
            currSeq = baseSeq;
        } else {
            currAck = ntohl(tcpHdr->seq) + payloadDataLen;
            currSeq = ntohl(tcpHdr->ack_seq);
        }
        bytesReceived = 0;
        lastBytesReceived = 0;
        currPeerWindow = ntohs(tcpHdr->window);
        S_WSS = getWindowScale(tcpHdr);
        connected = false;
    }

    void receiveAck(int vpnFd, uint8_t controlFlags){
        struct iphdr* ipHdr = (struct iphdr*) customHeaders;
        struct tcphdr* tcpHdr = (struct tcphdr*) (customHeaders + 20);

        ipHdr->tot_len = htons(40);
        compute_ip_checksum(ipHdr);

        tcpHdr->th_flags = controlFlags;
        tcpHdr->ack_seq = htonl(currAck);
        tcpHdr->seq = htonl(currSeq);
        compute_tcp_checksum(ipHdr, (unsigned short *) tcpHdr);

        char buffer [81];
        buffer[80] = 0;
        for(int j = 0; j < 40; j++)
            sprintf(&buffer[2*j], "%02X", customHeaders[j]);
        __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP receive: %s %d\n", buffer, controlFlags & 0xff);

        write(vpnFd, customHeaders, 40);
    }

    void receiveData(int vpnFd, int packetLen){
        struct iphdr* ipHdr = (struct iphdr*) customHeaders;
        struct tcphdr* tcpHdr = (struct tcphdr*) (customHeaders + 20);

        ipHdr->id += htons(1);
        ipHdr->tot_len = htons(40 + packetLen);
        compute_ip_checksum(ipHdr);

        tcpHdr->th_flags = TH_ACK | TH_PUSH;
        tcpHdr->ack_seq = htonl(currAck);
        tcpHdr->seq = htonl(currSeq);
        memcpy((customHeaders + 40), dataReceived, packetLen);
        compute_tcp_checksum(ipHdr, (unsigned short *) tcpHdr);

        char buffer [2*(40 + packetLen)+1];
        buffer[2*(40 + packetLen)] = 0;
        for(int j = 0; j < (40 + packetLen); j++)
            sprintf(&buffer[2*j], "%02X\n", customHeaders[j]);

        __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP receiveData: %s\n", buffer);

        write(vpnFd, customHeaders, (40 + packetLen));
    }

    void updateLastPacket(tcphdr *tcpHdr, int payloadDataLen) {
        currAck += payloadDataLen;
        if (ntohl(tcpHdr->ack_seq) > currSeq)
            currSeq = ntohl(tcpHdr->ack_seq);
        if (ntohl(tcpHdr->ack_seq) > lastAckSent)
            lastAckSent = ntohl(tcpHdr->ack_seq);
        currPeerWindow = ntohs(tcpHdr->window);
    }

    int bytesAcked(){
        if (lastAckSent > 0)
            return (lastAckSent - baseSeq) -1;
        return 0;
    }

    int getAdjustedCurrPeerWindowSize() {
        return currPeerWindow << S_WSS;
    }

};



class UdpConnection : public VpnConnection {

public:
    double lastTime;
    ip* LastIpPacket;
    udphdr * LastUdpPacket;

    void changeHeader(struct ip* ipHdr, struct udphdr* udpHdr) {

        struct in_addr auxIp = ipHdr->ip_src;
        // in_addr only for ipv4
        ipHdr->ip_src = ipHdr->ip_dst;
        ipHdr->ip_dst = auxIp;
        LastIpPacket=ipHdr;

        uint16_t auxPort= udpHdr->uh_sport;
        udpHdr->uh_sport = udpHdr->uh_dport;
        udpHdr->uh_dport = auxPort;
        LastUdpPacket= udpHdr;

    }

    double timeNow_millis(void) {
        struct timespec tm;
        clock_gettime(CLOCK_REALTIME, &tm);
        return 1000.0 * tm.tv_sec + (double)tm.tv_nsec/ 1e6;
    }

    UdpConnection(std::string mKey, int mSd, uint8_t *packet, uint16_t ipHdrLen,
                  uint16_t udpHdrLen) : VpnConnection(mKey, mSd, IPPROTO_UDP){
        key = mKey;
        sd = mSd;
        memcpy(customHeaders, packet, ipHdrLen + udpHdrLen);
        changeHeader((ip *) customHeaders, (udphdr *) (customHeaders + ipHdrLen));
        lastTime= timeNow_millis();

    }
    void receiveData(int vpnFd, int packetLen) {
        struct iphdr *ipHdr = (struct iphdr *) customHeaders;
        struct udphdr *udpHdr = (struct udphdr *) (customHeaders + 20);

        ipHdr->id += htons(1);
        ipHdr->tot_len = htons(40 + packetLen);
        compute_ip_checksum(ipHdr);
        memcpy((customHeaders + 40), dataReceived, packetLen);

        compute_udp_checksum(ipHdr, (unsigned short *) udpHdr);
        write(vpnFd, customHeaders, (40 + packetLen));
    }

    void updateLastPkt(uint8_t* pkt) {
        lastTime= timeNow_millis();
        queue.push(pkt);
    }

    udphdr* getLastUdpPacket() { return LastUdpPacket; }
    ip* getLastIpPacket() { return LastIpPacket; }

};


