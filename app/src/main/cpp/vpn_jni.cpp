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
#include "vpn_connection.h"

bool VPN_BYTES_AVIALABLE;

static std::unordered_map<std::string, VpnConnection*> udpMap;
static std::unordered_map<std::string, VpnConnection*> tcpMap;


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
  so its traffic will not be forwarded through the VPN" */
int protect(int sd){
    uint32_t intValue = 0x20000;
    socklen_t len = sizeof(intValue);

    if (setsockopt(sd, SOL_SOCKET, SO_MARK, &intValue, sizeof(intValue)) < 0) {
        perror("Protect Raw Socket failed");
        exit(EXIT_FAILURE);
    }
    return 1;
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

void sendPackets(VpnConnection *connection) {
    if(connection->protocol == TCP_PROTOCOL){
        int tcpSd = connection->sd;
    }
}

void startSniffer(int fd){
    std::string ipSrc, ipDst;
    std::string udpKey, tcpKey;
    std::string srcPort, desPort


    unsigned char packet[65536];
    int bytes_read;
    while(VPN_BYTES_AVIALABLE){
        bytes_read = read(fd, packet, 65536);

        if (bytes_read <= 0){
            VPN_BYTES_AVIALABLE = false;
            break;
        }

        uchar ipVer = packet[0] >> 4;

        //TODO: ipv6
        struct ip *ipHdr= (struct ip*) packet;
        int ipHdrLen = ipHdr->ip_hl * 4;
        int packetLen = ipHdr->ip_len;

        ipSrc = inet_ntoa(ipHdr->ip_src);
        ipDst = inet_ntoa(ipHdr->ip_dst);
        // if UDP

        if (packet[9] == UDP_PROTOCOL){

            packet+=ipHdrLen;
            udp =(struct udphdr *) packet;
            srcPort= ntohs(udp->uh_sport)
            desPort= ntohs(udp->uh_dport)
            udpKey = "" + srcPort + "-" + ipDst + "-" + desPort;
            VpnConnection* currentChannel;
            channelRecovered = false;
             try {
                    if (udpMap.containsKey(udpKey)) 
                    {
                        currentChannel = udpMap.get(udpKey);
                        currentChannel.keyFor(this.selector).attachment().updateLastPkt(uDPPacket);
                        writeChannel(currentChannel.keyFor(this.selector), fileOutputStream, false);
                        channelRecovered = true;
                    }
            } catch (Throwable e) 
                {
                    udpMap.remove(udpKey);
                    channelRecovered = false;

                    }

        }
        // if TCP
        else if (packet[9] == TCP_PROTOCOL){
            struct tcphdr *tcpHdr = (struct tcphdr *) packet + ipHdrLen;
            int tcpHdrLen = tcpHdr->doff * 4;


            ipSrc = ipSrc + ":" + to_string(ntohs(tcpHdr->source));
            ipDst = ipDst + ":" + to_string(ntohs(tcpHdr->dest));

            std::string tcpKey = ipSrc + "+" + ipDst;

            VpnConnection *tcpConnection;
            if(tcpMap.count(tcpKey) == 0){
                if(tcpHdr->syn && !tcpHdr->ack){
                    int tcpSd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
                    protect(tcpSd);

                    struct sockaddr_in sin;
                    sin.sin_family = AF_INET;
                    sin.sin_addr.s_addr = ipHdr->ip_dst.s_addr;
                    sin.sin_port = htons(tcpHdr->dest);

                    connect(tcpSd, (struct sockaddr *)&sin, sizeof(sin));

                    tcpMap.insert(std::make_pair(tcpKey, tcpConnection));

                }
            } else {
                tcpConnection = tcpMap.at(tcpKey);
                int tcpSd = tcpConnection->sd;

                if(tcpHdr->fin){

                } else if(tcpHdr->rst){

                } else if(!tcpHdr->syn && tcpHdr->ack){
                    int payloadDataLen = packetLen - ipHdrLen - tcpHdrLen;
                    if(payloadDataLen > 0){
                        tcpConnection->packetQueue.push(std::make_pair(packet, packetLen));
                        sendPackets(tcpConnection);
                    } else{

                    }

                }

            }

        }
    }
}



extern "C" {
    JNIEXPORT jint JNICALL
    Java_cl_niclabs_vpnpassiveping_AutoVpnService_startVPN(
            JNIEnv *env, jobject thiz, jobject fileDescriptor) {

        int fd = getFileDescriptor(env, fileDescriptor);

        startSniffer(fd);

        return (jint) fd;
    }
}