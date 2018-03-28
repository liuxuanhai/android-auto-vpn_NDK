#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <time.h>
#include "ipnetwork.h"
#include <stdio.h>


/* Convert an ip struct to a string. The returned buffer is internal, 
 and need not be freed.*/ 
/*char * iptostr(ip_hdr * ip, char* conf) {

    if (ip->vers == IPv4) {
    	if(conf=="s")
    	{
    	inet_ntop(AF_INET, (const void *) &((ip->type.ip4hdr)->ip_src),
                  IP_STR_BUFF, INET6_ADDRSTRLEN);	
    	}
    	else if(conf=="d"){
        inet_ntop(AF_INET, (const void *) &((ip->type.ip4hdr)->ip_dst),
                  IP_STR_BUFF, INET6_ADDRSTRLEN);
		}

		} 

    else { // IPv6
    	if(conf=="s")
    	{
    		inet_ntop(AF_INET6, (const void *) &((ip->type.ip6hdr)->ip6_src),
                  IP_STR_BUFF, INET6_ADDRSTRLEN);
    	}
    	else{
        	inet_ntop(AF_INET6, (const void *) &((ip->type.ip6hdr)->ip6_dst),
                  IP_STR_BUFF, INET6_ADDRSTRLEN);
    	}
    }
    return IP_STR_BUFF;
}*/

/* looks through tcp options and finds tcp timestaps if available*/
int options(unsigned char * packet, tcp_opt *tcp, unsigned int packet_lenght){
    int position = 20; //tcp header
    uint8_t lenght, kind;
    uint32_t tsval_1, tsval_2, tsval_3, tsval_4;
    uint32_t tsecr_1, tsecr_2, tsecr_3, tsecr_4;

    do 
    {
        kind= packet[position];
        switch(kind)
        {
            case 0:
            case 1:
                lenght=1;
                break;
            case 8:
                lenght= packet[position+1];

                tcp->kind = packet[position];
                tcp->length= packet[position +1];

                tsval_1 = ((uint32_t)packet[position+2])<<24;
                tsval_2 = ((uint32_t)packet[position+3])<<16;
                tsval_3 = ((uint32_t)packet[position+4])<<8;
                tsval_4 = ((uint32_t)packet[position+5]);

                tsecr_1 = ((uint32_t)packet[position+6])<<24;
                tsecr_2 = ((uint32_t)packet[position+7])<<16;
                tsecr_3 = ((uint32_t)packet[position+8])<<8;
                tsecr_4 = ((uint32_t)packet[position+9]);

                tcp->tsval = tsval_1 + tsval_2 + tsval_3 + tsval_4;
                tcp->tsecr = tsecr_1 + tsecr_2 + tsecr_3 + tsecr_4;

                return 0;
            default:
                lenght= packet[position+1];
                break;
        }
        position+=lenght;
    }
    while( packet_lenght-position >= 10);
    return -1;

}


/* return current time */
struct timespec time_now(void) {
    struct timespec tm;
    clock_gettime(CLOCK_REALTIME, &tm);
    return tm;

}

double seconds(struct timespec tm){
    return tm.tv_sec + (double)tm.tv_nsec/1e9;

}

double microseconds(struct timespec tm){
    return 1000000.0 * tm.tv_sec + (double)tm.tv_nsec/ 1e3;
}