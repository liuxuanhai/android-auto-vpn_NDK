#include <string>
#include <unordered_map>
#include <list>
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
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include "vpn_connection.h"


bool VPN_BYTES_AVIALABLE = true;
bool RUNNING = true;
int epollFd;
double t_cleanUp =10.0; /* required time elapsed for clean up of records*/
static std::unordered_map<std::string, UdpConnection*> udpMap;
static std::unordered_map<std::string, TcpConnection*> tcpMap;
static std::unordered_map<std::string, std::list<tcp_info> > flowRec;

JNIEnv* jniEnv;
jobject jObject;
jmethodID protectMethod;
FILE *rttFile;
template <typename T>
std::string to_string(T value){
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
        //__android_log_print(ANDROID_LOG_ERROR, "JNI ","protected socket: %d", sd);
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



void receivePackets(VpnConnection *connection, int vpnFd);
void connectSocket(TcpConnection *connection, int vpnFd);
void getRTT(TcpConnection *connection);
void alarm_handler(int);
uint16_t getIP6len(unsigned char * packet);



void sendPackets(VpnConnection *connection, int vpnFd) {


    if(connection->getProtocol() == IPPROTO_UDP) {

        UdpConnection *udpConnection= (UdpConnection*) connection;
        int udpSd= udpConnection->getSocket();

        while (!udpConnection->queue.empty()){

            //mandar solo datagram info
            uint8_t* ipPacket = udpConnection->queue.front();
            struct ip *ipHdr= (struct ip*) ipPacket;
            uint16_t ipHdrLen = ipHdr->ip_hl * 4;
            uint16_t packetLen = ntohs(ipHdr->ip_len);
            uint16_t udpHdrLen = 8;

            uint16_t payloadDataLen = packetLen - ipHdrLen - udpHdrLen;
            uint8_t* packetData = ipPacket + ipHdrLen + udpHdrLen;
            int bytesSent = send(udpSd, packetData, payloadDataLen, 0);
            __android_log_print(ANDROID_LOG_ERROR, "JNI ","UDP Sending packet %u %u %u", packetLen, ipHdrLen, udpHdrLen);
            free(ipPacket);
            udpConnection->queue.pop();

        }

    }

    if(connection->getProtocol() == IPPROTO_TCP){

        TcpConnection *tcpConnection = (TcpConnection*) connection;

        if(!tcpConnection->connected){
            connectSocket(tcpConnection, vpnFd);
            return;
        }

        int tcpSd = tcpConnection->getSocket();

        while (!tcpConnection->queue.empty()){

            uint8_t* ipPacket = tcpConnection->queue.front();

            //TODO: ipv6
            struct ip *ipHdr= (struct ip*) ipPacket;
            uint16_t ipHdrLen = ipHdr->ip_hl * 4;
            uint16_t packetLen = ntohs(ipHdr->ip_len);

            tcphdr* tcpHdr = (tcphdr*) (ipPacket + ipHdrLen);

            uint16_t tcpHdrLen = tcpHdr->doff * 4;
            uint16_t payloadDataLen = packetLen - ipHdrLen - tcpHdrLen;

            //__android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP Sending packet %d %d %d", packetLen, ipHdrLen, tcpHdrLen);


            if(ntohl(tcpHdr->seq) >= tcpConnection->currAck) {

                uint8_t* packetData = ipPacket + ipHdrLen + tcpHdrLen;
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
                free(ipPacket);
                tcpConnection->queue.pop();
            }
        }
        if (tcpConnection->queue.empty()){
            tcpConnection->ev.events = EPOLLIN;
            if (epoll_ctl(epollFd, EPOLL_CTL_MOD, tcpConnection->getSocket(), &tcpConnection->ev) == -1) {
                perror("epoll_ctl: read_sock");
                exit(EXIT_FAILURE);
            }
        }
    }
}

void  getRTT(TcpConnection* tcpConnection){
    int tcpSd= tcpConnection->getSocket();
    struct tcp_info ti;
    socklen_t tisize = sizeof(ti);
    //__android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP RTT1 %u %u", (unsigned long) ti.tcpi_rtt, ti.tcpi_min_rtt);

    getsockopt(tcpSd, IPPROTO_TCP, TCP_INFO, &ti, &tisize);
    std::string key = tcpConnection->ipDest;
    //__android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP RTT2 %u %u", (unsigned long) ti.tcpi_rtt, ti.tcpi_min_rtt);
    /* add connection to flowRec*/
    if(flowRec.count(key)==0) {
        std::list <tcp_info> tcpinfos;
        tcpinfos.push_front(ti);
        flowRec.emplace(key,tcpinfos);
    }
    else
    {
        auto item= flowRec.find(key);
        item->second.push_front(ti);
    }

    /* open a file and write results into it
    FILE *fp = fopen("rtts.txt", "ab+");
    fprintf(fp,"%s:","%zu\n",c_key, rtt);
    printf("%s:","%zu\n", c_key, rtt);
    fclose(fp);*/
}

void alarm_handler(int){
    while (!flowRec.empty()) {

        std::string key = flowRec.begin()->first;
        std::list<tcp_info> tcpinfos =flowRec.begin()->second;
        tcp_info ti= tcpinfos.front();
        u_int32_t minRtt= ti.tcpi_rtt;
        while(tcpinfos.size()!=0){
            tcp_info ti= tcpinfos.front();
            if( ti.tcpi_rtt< minRtt) minRtt= ti.tcpi_rtt;
            tcpinfos.pop_front();
        }

        /* copy tcpconnection key into chararray*/
        char *c_key = new char[key.length() + 1];
        strcpy(c_key, key.c_str());

        time_t rawtime;
        time(&rawtime);
        /* print information from flowRec*/
        int rc = fprintf(rttFile, "%s,%u,%d\n", c_key, minRtt, rawtime);
        __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP RTT alarm %s %u %d", c_key, minRtt, rawtime);
        if (rc<0)
            __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP RTT alarm %s %d", strerror(errno), rc);

        /* delete current stored value for connection */
        flowRec.erase(key);

    }
    fflush(rttFile);
    alarm(10);

}

void receivePackets(VpnConnection *connection, int vpnFd) {

    if(connection->getProtocol() == IPPROTO_UDP) {
        UdpConnection *udpConnection = (UdpConnection *) connection;
        int udpSd = udpConnection->getSocket();
        int bytes_read= recv(udpSd, udpConnection->dataReceived, IP_MAXPACKET - 28, 0);
        if (bytes_read <= 0) {
            //__android_log_print(ANDROID_LOG_ERROR, "JNI ","bytes read %d", bytes_read);
            return;
        }
        __android_log_print(ANDROID_LOG_ERROR, "JNI ","UDP read %d", bytes_read);

        udpConnection->receiveData(vpnFd, bytes_read);
    }
    if(connection->getProtocol() == IPPROTO_TCP){

        TcpConnection *tcpConnection = (TcpConnection*) connection;
        int tcpSd = tcpConnection->getSocket();

        int bytesSinceLastAck = tcpConnection->bytesReceived - tcpConnection->bytesAcked();
        int packetLen = -1;

        //__android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP read %d", bytesSinceLastAck);

        if (tcpConnection->getAdjustedCurrPeerWindowSize() != 0) {
            //__android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP read %d", tcpConnection->getAdjustedCurrPeerWindowSize());

            if (bytesSinceLastAck >= tcpConnection->getAdjustedCurrPeerWindowSize())
                return;
            else if (tcpConnection->lastBytesReceived > 0){
                packetLen = tcpConnection->lastBytesReceived;
                tcpConnection->lastBytesReceived = 0;
            }
            else {
                packetLen = recv(tcpSd, tcpConnection->dataReceived, IP_MAXPACKET - 40, 0);
            }
        }
        if (packetLen == 0){
            close(tcpSd);
            epoll_ctl(epollFd, EPOLL_CTL_DEL, tcpSd, &tcpConnection->ev);
            tcpMap.erase(tcpConnection->key);
            delete tcpConnection;
            return;
        }

        if (packetLen < 0)
            return;
        //__android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP read %d", packetLen);

        int remainingBytes = tcpConnection->getAdjustedCurrPeerWindowSize() - bytesSinceLastAck;
        //__android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP read %d", remainingBytes);

        if (packetLen > remainingBytes){
            packetLen = remainingBytes;
            tcpConnection->lastBytesReceived = packetLen - remainingBytes;
        }

        tcpConnection->receiveData(vpnFd, packetLen);

        tcpConnection->currSeq += packetLen;

        tcpConnection->bytesReceived += packetLen;
        getRTT(tcpConnection);

    }
}

void connectSocket(TcpConnection *tcpConnection, int vpnFd) {
    tcpConnection->receiveAck(vpnFd, TH_ACK | TH_SYN);
    tcpConnection->connected = true;

    tcpConnection->ev.events = EPOLLIN;
    if (epoll_ctl(epollFd, EPOLL_CTL_MOD, tcpConnection->getSocket(), &tcpConnection->ev) == -1) {
        perror("epoll_ctl: read_sock");
        exit(EXIT_FAILURE);
    }
}


void startSniffer(int fd) {
    rttFile = fopen("/storage/emulated/0/rtt.txt", "r+");
    /* set alarm for 10 seconds*/
    signal(SIGALRM, alarm_handler);
    alarm(10);

    epollFd = epoll_create( 0xD1E60 );
    if (epollFd < 0)
        exit(EXIT_FAILURE); // report error


    std::string ipSrc, ipDst;
    std::string udpKey, tcpKey;

    unsigned char packet[65536];
    int bytes_read;
    while(RUNNING) {
        while (VPN_BYTES_AVIALABLE) {
            bytes_read = read(fd, packet, 65536);

            if (bytes_read <= 0) {
                //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "No bytes!");
                //VPN_BYTES_AVIALABLE = false;
                break;
            }

            uint8_t ipVer = 4;

            //TODO: ipv6
            struct ip *ipHdr = (struct ip *) packet;
            uint16_t ipHdrLen = ipHdr->ip_hl * 4;
            uint16_t packetLen = ntohs(ipHdr->ip_len);

            ipSrc = inet_ntoa(ipHdr->ip_src);
            ipDst = inet_ntoa(ipHdr->ip_dst);
            // if UDP

            if (packet[9] == IPPROTO_UDP) {

                struct udphdr *udpHdr = (struct udphdr *) (packet + ipHdrLen);
                int udpHdrLen = udpHdr->uh_ulen * 4;
                ipSrc = ipSrc + ":" + to_string(ntohs(udpHdr->uh_sport));
                ipDst = ipDst + ":" + to_string(ntohs(udpHdr->uh_dport));
                std::string udpKey = ipSrc + "+" + ipDst;

                if (udpMap.count(udpKey) == 0) {
                    int udpSd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
                    protect(udpSd);
                    struct sockaddr_in sin;
                    sin.sin_family = AF_INET;
                    sin.sin_addr.s_addr = ipHdr->ip_dst.s_addr;
                    sin.sin_port = udpHdr->uh_dport;
                    int res = connect(udpSd, (struct sockaddr *) &sin, sizeof(sin));

                    __android_log_print(ANDROID_LOG_ERROR, "JNI ", "UDP Connect socket for: %s %d",
                                        ipDst.c_str(), res);
                    UdpConnection *udpConnection = new UdpConnection(udpKey, udpSd, packet, ipHdrLen, udpHdrLen);
                    udpMap.insert(std::make_pair(udpKey, udpConnection));
                    udpConnection->ev.events = EPOLLIN;
                    udpConnection->ev.data.ptr = udpConnection;

                    uint8_t *newPacket = (uint8_t *) malloc(packetLen);
                    memcpy(newPacket, packet, packetLen);
                    udpConnection->queue.push(newPacket);
                    sendPackets(udpConnection, fd);

                    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, udpSd, &udpConnection->ev) == -1) {
                        perror("epoll_ctl: listen_sock");
                        exit(EXIT_FAILURE);
                    }
                    sendPackets(udpConnection, fd);
                }
                else {
                    UdpConnection *udpConnection = udpMap.at(udpKey);
                    uint8_t *newPacket = (uint8_t *) malloc(packetLen);
                    memcpy(newPacket, packet, packetLen);
                    udpConnection->queue.push(newPacket);
                    sendPackets(udpConnection, fd);
                }
            }

                // if TCP
            else if (packet[9] == IPPROTO_TCP) {

                struct tcphdr *tcpHdr = (struct tcphdr *) (packet + ipHdrLen);
                uint16_t tcpHdrLen = tcpHdr->doff * 4;
                uint16_t payloadDataLen = packetLen - ipHdrLen - tcpHdrLen;


                ipSrc = ipSrc + ":" + to_string(ntohs(tcpHdr->source));
                ipDst = ipDst + ":" + to_string(ntohs(tcpHdr->dest));

                //__android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP Packet to: %s %d %d %d", ipDst.c_str(), packetLen, ipHdrLen, tcpHdrLen);

                char buffer[2 * (ipHdrLen + tcpHdrLen) + 1];
                buffer[2 * (ipHdrLen + tcpHdrLen)] = 0;
                for (int j = 0; j < (ipHdrLen + tcpHdrLen); j++)
                    sprintf(&buffer[2 * j], "%02X", packet[j]);
                //__android_log_print(ANDROID_LOG_ERROR, "JNI ","packet: %s \n", buffer);

                std::string tcpKey = ipSrc + "+" + ipDst;

                if (tcpMap.count(tcpKey) == 0) {
                    //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "TCP Not found key: %s %x",
                    //tcpKey.c_str(), tcpHdr->th_flags & 0xff);

                    if (tcpHdr->syn && !tcpHdr->ack) {

                        int tcpSd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
                        protect(tcpSd);
                        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "TCP Creating socket ");

                        struct sockaddr_in sin;
                        sin.sin_family = AF_INET;
                        //ipv4
                        sin.sin_addr.s_addr = ipHdr.type.v4->ip_dst.s_addr;
                        //todo ipv6
                        sin.sin_port = tcpHdr->dest;

                        int res = connect(tcpSd, (struct sockaddr *) &sin, sizeof(sin));

                        TcpConnection *tcpConnection = new TcpConnection(tcpKey,ipDst, tcpSd,packet,
                                                                         true, ipHdrLen, tcpHdrLen,
                                                                         payloadDataLen);

                        tcpConnection->ev.events = EPOLLOUT;
                        tcpConnection->ev.data.ptr = tcpConnection;

                        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, tcpSd, &tcpConnection->ev) == -1) {
                            perror("epoll_ctl: listen_sock");
                            exit(EXIT_FAILURE);
                        }

                        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "TCP Connect socket: %d %s",
                        //res, strerror(errno));
                        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "TCP Connect socket: %d %x",
                        //tcpSd, tcpConnection);

                        tcpMap.insert(std::make_pair(tcpKey, tcpConnection));

                    } else if (tcpHdr->fin || tcpHdr->ack) {
                        TcpConnection tcpConnection(tcpKey,ipDst, NULL, packet, false, ipHdrLen,
                                                    tcpHdrLen, payloadDataLen);
                        tcpConnection.currAck++;
                        tcpConnection.receiveAck(fd, TH_RST);

                    }
                } else {
                    TcpConnection *tcpConnection = tcpMap.at(tcpKey);
                    int tcpSd = tcpConnection->getSocket();

                    if (tcpHdr->fin) {
                        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "TCP FIN Packet to: %s %d",
                        //                    ipDst.c_str(), payloadDataLen);

                        tcpConnection->updateLastPacket(tcpHdr, payloadDataLen);

                        tcpConnection->currAck++;
                        tcpConnection->receiveAck(fd, TH_ACK | TH_FIN);
                        close(tcpSd);
                        epoll_ctl(epollFd, EPOLL_CTL_DEL, tcpSd, &tcpConnection->ev);
                        delete tcpConnection;
                        tcpMap.erase(tcpKey);
                    } else if (tcpHdr->rst) {
                        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "TCP RST Packet to: %s %d",
                        //                    ipDst.c_str(), payloadDataLen);

                        tcpConnection->receiveAck(fd, TH_RST);
                        close(tcpSd);
                        epoll_ctl(epollFd, EPOLL_CTL_DEL, tcpSd, &tcpConnection->ev);
                        delete tcpConnection;
                        tcpMap.erase(tcpKey);
                    } else if (!tcpHdr->syn && tcpHdr->ack) {
                        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "TCP ACK Packet to: %s %d",
                        //                    ipDst.c_str(), payloadDataLen);

                        if (payloadDataLen > 0) {
                            uint8_t *newPacket = (uint8_t *) malloc(packetLen);
                            memcpy(newPacket, packet, packetLen);
                            tcpConnection->queue.push(newPacket);
                            sendPackets(tcpConnection, fd);
                        } else {
                            tcpConnection->updateLastPacket(tcpHdr, payloadDataLen);
                        }

                    }

                }

            }
        }

        struct epoll_event events[20];
        int n = epoll_wait(epollFd, events, 20, 0);
        if(n>0)
            //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "EPOLL N: %d", n);

            for (int i = 0; i < n; i++) {
                struct epoll_event ev = events[i];
                //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "EPOLL fd: %d %x", ((VpnConnection*)ev.data.ptr)->getSocket(),((VpnConnection*)ev.events) );

                if (ev.events & EPOLLOUT)
                    sendPackets((VpnConnection *) ev.data.ptr, fd);
                if (ev.events & EPOLLIN)
                    receivePackets((VpnConnection *) ev.data.ptr, fd);
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