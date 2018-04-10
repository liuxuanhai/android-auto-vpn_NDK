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