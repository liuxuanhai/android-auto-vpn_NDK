#include <queue>

#define TCP_PROTOCOL    6
#define UDP_PROTOCOL    17

typedef unsigned char uchar;

typedef struct vpn_connection {
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

    std::queue<std::pair<uchar*, int>> packetQueue;
} VpnConnection;