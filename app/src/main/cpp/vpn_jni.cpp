#include <string>
#include <unordered_map>
#include <sstream>
#include <jni.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <android/log.h>
#include <string.h>
#include <errno.h>
#include "vpn_connection.h"

bool VPN_BYTES_AVIALABLE = true;

static std::unordered_map<std::string, UdpConnection> udpMap;
static std::unordered_map<std::string, TcpConnection> tcpMap;

JNIEnv* jniEnv;
jobject jObject;
jmethodID protectMethod;

template <typename T>
std::string to_string(T value)
{
    std::ostringstream os ;
    os << value ;
    return os.str() ;
}

/* Simulates Android VpnService protect() function in order to protect
  raw socket from VPN connection. So, according to Android reference,
  "data sent through this socket will go directly to the underlying network,
  so its traffic will not be forwarded through the VPN"*/
int protect(int sd){
    jboolean res = jniEnv->CallBooleanMethod(jObject, protectMethod, sd);
    if(res){
        __android_log_print(ANDROID_LOG_ERROR, "JNI ","protected socket: %d", sd);
        return 1;
    }
    return 0;
}

/* Get file descriptor number from Java object FileDescriptor */
int getFileDescriptor(JNIEnv* env, jobject fileDescriptor) {
    jint fd = -1;

    jclass fdClass = env->FindClass( "java/io/FileDescriptor");

    if (fdClass != NULL) {
        jfieldID fdClassDescriptorFieldID = env->GetFieldID(fdClass, "descriptor", "I");
        if (fdClassDescriptorFieldID != NULL && fileDescriptor != NULL) {
            fd = env->GetIntField(fileDescriptor, fdClassDescriptorFieldID);
        }
    }
    __android_log_print(ANDROID_LOG_ERROR, "JNI ","VPN fd: %d", fd);

    return fd;
}

void sendPackets(VpnConnection *connection, int vpnFd) {

    if(connection->getProtocol() == UDP_PROTOCOL) {
        UdpConnection *udpConnection= (UdpConnection*) connection;
        int udpSd= udpConnection->getSocket();

        while (!udpConnection->queue.empty()){
        //mandar solo datagram info
            uchar* ipPacket = udpConnection->queue.front();
            struct ip *ipHdr= (struct ip*) ipPacket;
            int ipHdrLen = ipHdr->ip_hl * 4;
            int packetLen = ipHdr->ip_len;
            udphdr* udpHdr = (udphdr*) ipPacket + ipHdrLen;
            int udpHdrLen = udpHdr->uh_ulen * 4;
            int payloadDataLen = packetLen - ipHdrLen - udpHdrLen;
            uchar* packetData = ipPacket + ipHdrLen + udpHdrLen;
            int bytesSent = 0;
            bytesSent += send(udpSd, packetData, payloadDataLen, 0);
            if(bytesSent < payloadDataLen){

            }
            else {
                __android_log_print(ANDROID_LOG_ERROR, "JNI ", "UDP Sending packet");
                udpConnection->queue.pop();
            }


        }


    }
    if(connection->getProtocol() == TCP_PROTOCOL){

        TcpConnection *tcpConnection = (TcpConnection*) connection;
        int tcpSd = tcpConnection->getSocket();

        while (!tcpConnection->queue.empty()){

            uchar* ipPacket = tcpConnection->queue.front();

            //TODO: ipv6
            struct ip *ipHdr= (struct ip*) ipPacket;
            uint16_t ipHdrLen = ipHdr->ip_hl * 4;
            uint16_t packetLen = ntohs(ipHdr->ip_len);

            tcphdr* tcpHdr = (tcphdr*) (ipPacket + ipHdrLen);

            uint16_t tcpHdrLen = tcpHdr->doff * 4;
            uint16_t payloadDataLen = packetLen - ipHdrLen - tcpHdrLen;

            __android_log_print(ANDROID_LOG_ERROR, "JNI ","Sending packet %d %d %d", packetLen, ipHdrLen, tcpHdrLen);


            if(ntohl(tcpHdr->seq) >= tcpConnection->currAck) {

                uchar* packetData = ipPacket + ipHdrLen + tcpHdrLen;
                int bytesSent = 0;

                bytesSent += send(tcpSd, packetData, payloadDataLen, 0);

                //TODO: socket error management

                if(bytesSent < payloadDataLen){
                    break;
                } else{
                    tcpConnection->queue.pop();
                    tcpConnection->currAck += bytesSent;
                    tcpConnection->receiveAck(vpnFd, TH_ACK);
                }
            } else{
                tcpConnection->queue.pop();
            }
        }
    }
}

void readPackets(VpnConnection *connection, int vpnFd) {

    if (connection->getProtocol() == UDP_PROTOCOL) {
        UdpConnection *udpConnection = (UdpConnection *) connection;
        int udpSd = udpConnection->getSocket();
        unsigned char packet[65536];
        int bytes_read= read(udpSd,packet,65556);
        if(bytes_read>0){
            udphdr* lastUdpHdr= udpConnection->getLastUdpPacket();


        }




    }
}


void startSniffer(int fd) {
    std::string ipSrc, ipDst;
    std::string udpKey, tcpKey;


    unsigned char packet[65536];
    int bytes_read;
    while(VPN_BYTES_AVIALABLE){
        bytes_read = read(fd, packet, 65536);

        if (bytes_read <= 0){
            //VPN_BYTES_AVIALABLE = false;
            continue;
        }

        uint8_t ipVer = 4;

        //TODO: ipv6
        struct ip *ipHdr= (struct ip*) packet;
        uint16_t ipHdrLen = ipHdr->ip_hl * 4;
        uint16_t packetLen = ntohs(ipHdr->ip_len);

        ipSrc = inet_ntoa(ipHdr->ip_src);
        ipDst = inet_ntoa(ipHdr->ip_dst);
        // if UDP

        if (packet[9] == UDP_PROTOCOL){
            struct udphdr* udpHdr =(struct udphdr *) (packet + ipHdrLen);
            int udpHdrLen = udpHdr->uh_ulen * 4;
            ipSrc = ipSrc + ":" + to_string(ntohs(udpHdr->uh_sport));
            ipDst = ipDst + ":" + to_string(ntohs(udpHdr->uh_dport));
            std::string udpKey = ipSrc + "+" + ipDst;
            bool channelRecovered = false;

            if (udpMap.count(udpKey)==0){
                __android_log_print(ANDROID_LOG_ERROR, "JNI ","UDP Not found key: %s", ipDst.c_str());
            }
            if(udpMap.count(udpKey)!=0){
                UdpConnection udpConnection = udpMap.at(udpKey);
                uchar* newPacket = (uchar*)malloc(packetLen);
                memcpy(newPacket, packet, packetLen);
                udpConnection.updateLastPkt(newPacket);
                sendPackets(&udpConnection, fd);
                channelRecovered = true;
            }
            if (!channelRecovered) {

                int udpSd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                protect(udpSd);
                struct sockaddr_in sin;
                sin.sin_family = AF_INET;
                sin.sin_addr.s_addr = ipHdr->ip_dst.s_addr;
                sin.sin_port = htons(udpHdr->uh_dport);
                int res = connect(udpSd, (struct sockaddr *)&sin, sizeof(sin));

                __android_log_print(ANDROID_LOG_ERROR, "JNI ","UDP Connect socket for: %s %d", ipDst.c_str(), res);
                UdpConnection udpConnection(udpKey, udpSd,packet, ipHdrLen, udpHdrLen);
                udpMap.insert(std::make_pair(udpKey, udpConnection));


            }
        }
            // if TCP
        else if (packet[9] == TCP_PROTOCOL){

            struct tcphdr *tcpHdr = (struct tcphdr *) (packet + ipHdrLen);
            int tcpHdrLen = tcpHdr->doff * 4;
            uint16_t payloadDataLen = packetLen - ipHdrLen - tcpHdrLen;


            ipSrc = ipSrc + ":" + to_string(ntohs(tcpHdr->source));
            ipDst = ipDst + ":" + to_string(ntohs(tcpHdr->dest));

            __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP Packet to: %s %d %d %d", ipDst.c_str(), packetLen, ipHdrLen, tcpHdrLen);

            char buffer [81];
            buffer[80] = 0;
            for(int j = 0; j < 40; j++)
                sprintf(&buffer[2*j], "%02X", packet[j]);
            __android_log_print(ANDROID_LOG_ERROR, "JNI ","packet: %s \n", buffer);

            std::string tcpKey = ipSrc + "+" + ipDst;

            if(tcpMap.count(tcpKey) == 0){
                __android_log_print(ANDROID_LOG_ERROR, "JNI ","Not found key: %s %x", tcpKey.c_str(), tcpHdr->th_flags & 0xff);

                if(tcpHdr->syn && !tcpHdr->ack){

                    int tcpSd = socket(AF_INET, SOCK_STREAM, 0);
                    protect(tcpSd);
                    __android_log_print(ANDROID_LOG_ERROR, "JNI ","Creating socket for: %s", ipDst.c_str());

                    struct sockaddr_in sin;
                    sin.sin_family = AF_INET;
                    sin.sin_addr.s_addr = ipHdr->ip_dst.s_addr;
                    sin.sin_port = tcpHdr->dest;

                    //TODO: wait connection with select/poll
                    int res = connect(tcpSd, (struct sockaddr *)&sin, sizeof(sin));

                    __android_log_print(ANDROID_LOG_ERROR, "JNI ","Connect socket for: %s %d %s", ipDst.c_str(), res, strerror(errno));

                    TcpConnection tcpConnection (tcpKey, tcpSd, packet, true, ipHdrLen, tcpHdrLen, payloadDataLen);

                    tcpMap.insert(std::make_pair(tcpKey, tcpConnection));

                    tcpConnection.receiveAck(fd, TH_ACK | TH_SYN);

                } else if(tcpHdr->fin || tcpHdr->ack){
                    TcpConnection tcpConnection (tcpKey, NULL, packet, false, ipHdrLen, tcpHdrLen, payloadDataLen);
                    tcpConnection.currAck++;
                    tcpConnection.receiveAck(fd, TH_RST);

                }
            } else {
                TcpConnection tcpConnection = tcpMap.at(tcpKey);
                int tcpSd = tcpConnection.getSocket();

                if(tcpHdr->fin){
                    __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP FIN Packet to: %s %d", ipDst.c_str(), payloadDataLen);

                    tcpConnection.updateLastPacket(tcpHdr, payloadDataLen);

                    tcpConnection.currAck++;
                    tcpConnection.receiveAck(fd, TH_ACK & TH_FIN);
                    close(tcpSd);
                    tcpMap.erase(tcpKey);
                } else if(tcpHdr->rst){
                    __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP RST Packet to: %s %d", ipDst.c_str(), payloadDataLen);

                    tcpConnection.receiveAck(fd, TH_RST);
                    close(tcpSd);
                    tcpMap.erase(tcpKey);
                } else if(!tcpHdr->syn && tcpHdr->ack){
                    __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP ACK Packet to: %s %d", ipDst.c_str(), payloadDataLen);

                    if(payloadDataLen > 0){
                        uchar* newPacket = (uchar*)malloc(packetLen);
                        memcpy(newPacket, packet, packetLen);
                        tcpConnection.queue.push(newPacket);
                        sendPackets(&tcpConnection, fd);
                    } else{
                        tcpConnection.updateLastPacket(tcpHdr, payloadDataLen);
                    }

                }
                __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP else Packet to: %s %x", ipDst.c_str(), tcpHdr->th_flags & 0xff);


            }

        }
    }
}



extern "C"{
JNIEXPORT jint JNICALL
Java_cl_niclabs_vpnpassiveping_AutoVpnService_startVPN(
        JNIEnv *env, jobject thiz, jobject fileDescriptor) {
    jniEnv = env;
    jObject = thiz;
    jclass clazz = env->FindClass("cl/niclabs/vpnpassiveping/AutoVpnService");
    protectMethod = env->GetMethodID(clazz, "protect", "(I)Z");

    int fd = getFileDescriptor(env, fileDescriptor);

    startSniffer(fd);

    return (jint) fd;
}
}