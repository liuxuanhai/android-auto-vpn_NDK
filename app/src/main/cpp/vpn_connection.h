#include <queue>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define TCP_PROTOCOL    6
#define UDP_PROTOCOL    17

typedef unsigned char uchar;

typedef struct udp_connection {
    std::string key;
    int sd; //Socket Descriptor
    uchar protocol; // 17:UDP, 6:TCP
    uchar *lastPacket;

    //TCP fields
    int currAck;
    int currSeq;
    int bytesSent;
    int bytesReceived;
    int lastAckReceived;

    std::queue<udphdr*> packetQueue;
} UdpConnection;


 public void EnqueuePkt(UdpConnection* udp, udphdr* pkt) {
        udp->packetQueue.push(pkt);
    }

 public void updateLastPkt(UdpConnection* udp, udphdr* pkt) {
        udp->lastTime = System.currentTimeMillis();
        EnqueuePkt(udp,pkt);
    }