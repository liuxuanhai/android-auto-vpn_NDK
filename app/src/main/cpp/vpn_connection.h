#include <queue>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define TCP_PROTOCOL    6
#define UDP_PROTOCOL    17

typedef unsigned char uchar;

class VpnConnection {

protected:
    std::string key;
    int sd; //Socket Descriptor
    uchar protocol; // 17:UDP, 6:TCP

public:
    std::queue<uchar*> queue;

    VpnConnection(std::string mKey, int mSd, uchar mProtocol) {
        key = mKey;
        sd = mSd;
        protocol = mProtocol;
    }

    uchar getProtocol() { return protocol; }
    int getSocket() { return sd; }
};

class TcpConnection : public VpnConnection {
    int bytesSent, bytesReceived;
    tcphdr lastHdr;

public:

    TcpConnection(std::string mKey, int mSd, tcphdr tcpHdr,
                  bool newKey, int payloadDataLen) : VpnConnection(mKey, mSd, TCP_PROTOCOL){
        key = mKey;
        sd = mSd;
        if(newKey){
            currAck = tcpHdr.seq + 1;
            currSeq = tcpHdr.seq;
        } else {
            currAck = tcpHdr.seq + payloadDataLen;
            currSeq = tcpHdr.ack;
        }
        lastHdr = tcpHdr;
    }

    uint32_t currAck;

    void receiveAck(int vpnFd, uint8_t controlFlags){


    }

    uint32_t currSeq;
    uint32_t lastAckReceived;

    void updateLastPacket(tcphdr *tcpHdr, int payloadDataLen) {
        currAck += payloadDataLen;
        if (tcpHdr->ack_seq > currSeq)
            currSeq = tcpHdr->ack_seq;
        if (tcpHdr->ack_seq > lastAckReceived)
            lastAckReceived = tcpHdr->ack_seq;
    }
};

/*
 public void EnqueuePkt(UdpConnection* udp, udphdr* pkt) {
        udp->packetQueue.push(pkt);
    }

 public void updateLastPkt(UdpConnection* udp, udphdr* pkt) {
        udp->lastTime = System.currentTimeMillis();
        EnqueuePkt(udp,pkt);
    }
*/