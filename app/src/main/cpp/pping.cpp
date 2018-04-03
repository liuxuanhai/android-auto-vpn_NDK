
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <ctime>
#include <sys/time.h>
#include <iostream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <utility>
#include <cmath>
#include <time.h>
#include <stdexcept>
#include "ipnetwork.h"
#define TCP_HDRLEN 20         // TCP header length, excludes options data


// Record of flow for each connection, updated in time
class flowRec
{
  public:
    explicit flowRec(std::string nm) 
    {
        flowname = std::move(nm);
    };
    ~flowRec() = default;

    std::string flowname;
    double last_tm{};
    double min{1e30};   // current min value for capturepoint-to-source RTT
    double bytesSnt{};  // number of bytes sent through CP toward dst
                        // inbound-to-CP, or return, direction
    double lstBytesSnt{};   //value of bytesSnt for flow at previous pping printing
    double bytesDep{};  // set on RTT sample computation for the stream for which
                        // this flow is the "forward" or outbound-from-mp direction.
                        // It is the value of this bytes_snt when a TSval entry was made
                        // and is set when an RTT is computed for this stream by getting a
                        // match on TSval entry by reverse flow, i.e. the number of bytes
                        // departed through CP the last time an RTT was computed for this stream
    bool revFlow{};             //inidcates if a reverse flow has been seen
};

template <typename T>
std::string to_string(T value)
{
    std::ostringstream os ;
    os << value ;
    return os.str() ;
}

class tsInfo
{
  public:
    explicit tsInfo(double tm, double f, double d)
        : t{tm}, fBytes{f}, dBytes{d} {};
    ~tsInfo() {};
    double t;       //wall clock time of new TSval pkt arrival
    double fBytes;  //total bytes of flow through CP including this pkt
    double dBytes;  //total bytes of in
};

static std::unordered_map<std::string, flowRec*> flows;
static std::unordered_map<std::string, tsInfo*> tsTbl;

#define SNAP_LEN 144                // maximum bytes per packet to capture
static double tsvalMaxAge = 10.;    // limit age of TSvals to use
static double flowMaxIdle = 300.;   // flow idle time until flow forgotten
static double sumInt = 10.;         // how often (sec) to print summary line
static int maxFlows = 10000;
static int flowCnt;
static double time_to_run;      // how many seconds to capture (0=no limit)
static int maxPackets;          // max packets to capture (0=no limit)
static int64_t offTm = -1;      // first packet capture time (used to
                                // avoid precision loss when 52 bit timestamp
                                // normalized into FP double 47 bit mantissa)
static bool machineReadable = false; // machine or human readable output
static double capTm, startm;        // (in seconds)
static int pktCnt, not_tcp, no_TS, not_v4or6, uniDir;
static std::string localIP;         // ignore pp through this address
static bool filtLocal = true;
static std::string filter("tcp");    // default bpf filter
static int64_t flushInt = 1 << 20;  // stdout flush interval (~uS)
static int64_t nextFlush;       // next stdout flush time (~uS)


// save capture time of packet using its flow + TSval as key.  If key
// exists, don't change it.  The same TSval may appear on multiple
// packets so this retains the first (oldest) appearance which may
// overestimate RTT but won't underestimate. This slight bias may be
// reduced by adding additional fields to the key (such as packet's
// ending tcp_seq to match against returned tcp_ack) but this can
// substantially increase the state burden for a small improvement.

static inline void addTS(const std::string& key, tsInfo* ti)
{
#ifdef __cpp_lib_unordered_map_try_emplace
    tsTbl.try_emplace(key, ti);
#else
    if (tsTbl.count(key) == 0) {
        tsTbl.emplace(key, ti);
    }
#endif
}

// A packet's ECR (timestamp echo reply) should match the TSval of some
// packet seen earlier in the flow's reverse direction so lookup the
// capture time recorded above using the reversed flow + ECR as key. If
// found, the difference between now and capture time of that packet is
// >= the current RTT. Multiple packets may have the same ECR but the
// first packet's capture time gives the best RTT estimate so the time
// in the entry is negated after retrieval to prevent reuse.  The entry
// can't be deleted yet because TSvals may change on time scales longer
// than the RTT so a deleted entry could be recreated by a later packet
// with the same TSval which could match an ECR from an earlier
// incarnation resulting in a large RTT underestimate.  Table entries
// are deleted after a time interval (tsvalMaxAge) that should be:
//  a) longer than the largest time between TSval ticks
//  b) longer than longest queue wait packets are expected to experience

static inline tsInfo* getTStm(const std::string& key)
{
    try {
        tsInfo* ti = tsTbl.at(key);
        return ti;
    } catch (const std::out_of_range& e) {
        return nullptr;
    }
}

static std::string fmtTimeDiff(double dt)
{
    const char* SIprefix = "";
    if (dt < 1e-3) {
        dt *= 1e6;
        SIprefix = "u";
    } else if (dt < 1) {
        dt *= 1e3;
        SIprefix = "m";
    } 
    const char* fmt;
    if (dt < 10.) {
        fmt = "%.2lf%ss";
    } else if (dt < 100.) {
        fmt = "%.1lf%ss";
    } else {
        fmt = " %.0lf%ss";
    }
    char buf[10];
    snprintf(buf, sizeof(buf), fmt, dt, SIprefix);
    return buf;
}

/*
 * return (approximate) time in a 64bit fixed point integer with the
 * binary point at bit 20. High accuracy isn't needed (this time is
 * only used to control output flushing) so time is stretched ~5%
 * ((1024^2)/1e6) to avoid a 64 bit multiply.
 */
static int64_t clock_now(void) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (int64_t(tv.tv_sec) << 20) | tv.tv_usec;
}




/*process packet received in buffer
saves ip header and tcp header
saves tcp timestamps if available*/


static void process_packet(unsigned char * packet, struct timespec tm){
    uint32_t rcv_tsval, rcv_tsecr;
    std::string srcstr, dststr, ipsstr, ipdstr;

    unsigned int IP_header_length;
    unsigned int TCP_packet_lenght;
    unsigned int Packet_lenght;

    struct ip *iphdr;
    //struct ip6_hdr *ip6hdr;
    struct tcphdr *tcp;
    struct tcp_opt t_opt;
    pktCnt++;
    int i;

    // looking into first byte of package 
    uint8_t ip_number= packet[0]>>4;

    // ip protocol not v4
    if(ip_number!=4)
        return;

    iphdr= (struct ip*) packet;
    IP_header_length = iphdr->ip_hl * 4;
    Packet_lenght = (packet[2]<<8) +packet[3];
   

    //ipv6 extension
    /*ip_number==4 ? iphdr = ( struct *ip) packet : ip6hdr= (struct * ip6_hdr) packet;    
    */
    ipsstr = inet_ntoa(iphdr->ip_src);
    ipdstr = inet_ntoa(iphdr->ip_dst);

    // transport layer ptrocol not TCP
    if (iphdr->ip_p != IPPROTO_TCP)
        return;
    
    packet += IP_header_length;
    tcp =(struct tcphdr *) packet;
    TCP_packet_lenght= (packet[12]>>4)*4;

    srcstr = ipsstr + ":" + to_string(ntohs(tcp->th_sport));
    dststr = ipdstr + ":" + to_string(ntohs(tcp->th_dport));
    
    // tcp has no option section 
    // revisar esto
    if(TCP_packet_lenght- TCP_HDRLEN<10)
    {
        no_TS++;
        return;
    }    
    // if tcp has option section, check if it is the one needed.    
    else{
        i=options(packet, &t_opt, TCP_packet_lenght);
    }

    // tcp options kind is different from 8
    if(i==-1)
    {
        no_TS++;
        return;
    }    

    rcv_tsval= t_opt.tsval;
    rcv_tsecr= t_opt.tsecr;

    //fprintf(stderr, "TS tsval: %d, tsecr: %d\n", rcv_tsval, rcv_tsecr);

    // The Timestamp Echo Reply field (TSecr) is only valid if the ACK bit is set in the TCP header

     if (t_opt.tsval == 0 || (rcv_tsecr == 0 && (tcp->th_flags != 0x02))) { //tcp_syn
        return;
    }


    //Process clock time
    std::time_t result = (time_t)seconds(tm);
    if (offTm < 0) {
        offTm = static_cast<int64_t>(seconds(tm));
        fprintf(stderr, "sunint %f\n", sumInt);

        // fractional part of first usable packet time
        startm = (static_cast<int64_t>(microseconds(tm))%1000000) * 1e-6;
            fprintf(stderr, "startm %f\n", startm);

        capTm = startm;
        if (sumInt) {
            std::cerr << "First packet at "
                      << std::asctime(std::localtime(&result)) << "\n";
        }
    } else {
        // offset capture time
        int64_t tt = static_cast<int64_t>(seconds(tm)) - offTm;
        capTm = double(tt + (static_cast<int64_t>(microseconds(tm))%1000000)* 1e-6);
    }

    std::string fstr = srcstr + "+" + dststr;  // could add DSCP field to key
    // Creates a flowRec entry whenever needed
    flowRec* fr;
    if (flows.count(fstr) == 0u) {
        if (flowCnt > maxFlows) {
            // stop adding flows till something goes away
            return; 
        }

        fr = new flowRec(fstr);
        flowCnt++;
        flows.emplace(fstr, fr);

        // only want to record tsvals when capturing both directions
        // of a flow. if this flow is the reverse of a known flow,
        // mark both as bi-directional.
        if (flows.count(dststr + "+" + srcstr) != 0u) {
            flows.at(dststr + "+" + srcstr)->revFlow = true;
            fr->revFlow = true;
        }
    } else {
        fr = flows.at(fstr);
    }
    fr->last_tm = capTm;

    if (! fr->revFlow) {
        uniDir++;
        return;
    }

    double arr_fwd = fr->bytesSnt + Packet_lenght;
    fr->bytesSnt = arr_fwd;
    if (!filtLocal || (localIP != ipdstr)) {
        addTS(fstr + "+" + to_string(rcv_tsval),
              new tsInfo(capTm, arr_fwd, fr->bytesDep));
    }
    tsInfo* ti = getTStm(dststr + "+" + srcstr + "+" +
                         to_string(rcv_tsecr));
    if (ti && ti->t > 0.0) {
    // this packet is the return "pping" --
        // process it for packet's src
        double t = ti->t;
        double rtt = capTm - t;
        if (fr->min > rtt) {
            fr->min = rtt;       //track minimum
        }
        double fBytes = ti->fBytes;
        double dBytes = ti->dBytes;
        double pBytes = arr_fwd - fr->lstBytesSnt;
        fr->lstBytesSnt = arr_fwd;
        flows.at(dststr + "+" + srcstr)->bytesDep = fBytes;

        if (!machineReadable) {
            printf("%" PRId64 ".%06d %.6f %.6f %.0f %.0f %.0f",
                    int64_t(t + offTm), int((t - floor(t)) * 1e6),
                    rtt, fr->min, fBytes, dBytes, pBytes);
        } else {
            char tbuff[80];
            struct tm* ptm = std::localtime(&result);
            strftime(tbuff, 80, "%T", ptm);
#ifdef notyet
            printf("%s %s %s %d", tbuff, fmtTimeDiff(rtt).c_str(),
                   fmtTimeDiff(fr->min).c_str(), (int)(fBytes - dBytes));
#else
            printf("%s %s %s", tbuff, fmtTimeDiff(rtt).c_str(),
                   fmtTimeDiff(fr->min).c_str());
#endif
        }
        printf(" %s\n", fstr.c_str());
        int64_t now = clock_now();
        if (now - nextFlush >= 0) {
            nextFlush = now + flushInt;
            fflush(stdout);
        }
        ti->t = -t;     //leaves an entry in the TS table to avoid saving this
                        // TSval again, mark it negative to indicate it's been used
    }
}

static void cleanUp(double n)
{
    // erase entry if its TSval was seen more than tsvalMaxAge
    // seconds in the past. 
    for (auto it = tsTbl.begin(); it != tsTbl.end();) {
        if (capTm - std::abs(it->second->t) > tsvalMaxAge) {
            delete it->second;
            it = tsTbl.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = flows.begin(); it != flows.end();) {
        flowRec* fr = it->second;
        if (n - fr->last_tm > flowMaxIdle) {
            delete it->second;
            it = flows.erase(it);
            flowCnt--;
            continue;
        }
        ++it;
    }
}

static inline std::string printnz(int v, const char *s) {
    return (v > 0? to_string(v) + s : "");
}

static void printSummary()
{
    std::cerr << flowCnt << " flows, "
              << pktCnt << " packets, " +
                 printnz(no_TS, " no TS opt, ") +
                 printnz(uniDir, " uni-directional, ") +
                 printnz(not_tcp, " not TCP, ") +
                 printnz(not_v4or6, " not v4 or v6, ") +
                 "\n";
}

static struct option opts[] = {
    { "read",      required_argument, nullptr, 'p' },
    { "filter",    required_argument, nullptr, 'f' },
    { "count",     required_argument, nullptr, 'c' },
    { "seconds",   required_argument, nullptr, 's' },
    { "quiet",     no_argument,       nullptr, 'q' },
    { "verbose",   no_argument,       nullptr, 'v' },
    { "showLocal", no_argument,       nullptr, 'l' },
    { "machine",   no_argument,       nullptr, 'm' },
    { "sumInt",    required_argument, nullptr, 'S' },
    { "tsvalMaxAge", required_argument, nullptr, 'M' },
    { "flowMaxIdle", required_argument, nullptr, 'F' },
    { "help",      no_argument,       nullptr, 'h' },
    { 0, 0, 0, 0 }
};

static void usage(const char* pname) {
    std::cerr << "usage: " << pname << " [flags] -i interface | -r pcapFile\n";
}

static void help(const char* pname) {
    usage(pname);
    std::cerr << " flags:\n"
"  -p|--read packet    process capture file <char*>\n"
"\n"
"  -f|--filter expr   pcap filter applied to packets.\n"
"                     Eg., \"-f 'net 74.125.0.0/16 or 45.57.0.0/17'\"\n" 
"                     only shows traffic to/from youtube or netflix.\n"
"\n"
"  -m|--machine       'machine readable' output format suitable\n"
"                     for graphing or post-processing. Timestamps\n"
"                     are printed as seconds since capture start.\n"
"                     RTT and minRTT are printed as seconds. All\n"
"                     times have a resolution of 1us (6 digits after\n"
"                     decimal point).\n"
"\n"
"  -c|--count num     stop after capturing <num> packets\n"
"\n"
"  -s|--seconds num   stop after capturing for <num> seconds \n"
"\n"
"  -q|--quiet         don't print summary reports to stderr\n"
"\n"
"  -v|--verbose       print summary reports to stderr every sumInt (10) seconds\n"
"\n"
"  -l|--showLocal     show RTTs through local host applications\n"
"\n"
"  --sumInt num       summary report print interval (default 10s)\n"
"\n"
"  --tsvalMaxAge num  max age of an unmatched tsval (default 10s)\n"
"\n"
"  --flowMaxIdle num  flows idle longer than <num> are deleted (default 300s)\n"
"\n"
"  -h|--help          print help then exit\n"
;
}


int receive_packet(unsigned char * pkt) 
{
    unsigned char *packet= pkt; 
    struct timespec tm;

    nextFlush = clock_now() + flushInt;
    double nxtSum = 0., nxtClean = 0.;

    tm = time_now();
    process_packet(packet,tm);

    if ((time_to_run > 0. && capTm - startm >= time_to_run) ||
        (maxPackets > 0 && pktCnt >= maxPackets)) 
        {
            printSummary();
            std::cerr << "Captured " << pktCnt << " packets in "
                      << (capTm - startm) << " seconds\n";
        }

    if (capTm >= nxtSum && sumInt) {
        if (nxtSum > 0.) {
            printSummary();
            pktCnt = 0;
            no_TS = 0;
            uniDir = 0;
            not_tcp = 0;
            not_v4or6 = 0;
            }
            nxtSum = capTm + sumInt;

        }

    if (capTm >= nxtClean) {
            cleanUp(capTm);  // get rid of stale entries
            nxtClean = capTm + tsvalMaxAge;
        }

    return 0;
}