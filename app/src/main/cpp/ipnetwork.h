#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <time.h>

typedef struct tcp_opt
{
    uint8_t kind;
    uint8_t length;
    uint32_t tsval;// Timestamp Value field
    uint32_t tsecr; //Timestamp Echo Reply field
} tcp_opt;


// general struct for both ip v6 or ip v4
typedef struct ip_hdr{
	uint8_t vers;
	union
	{
		struct ip *ip4hdr;
    	struct ip6_hdr *ip6hdr;
	} type;

} ip_hdr;


#define IPv4 0x04
#define IPv6 0x06

// structure for ip address (either 4 or 6)
typedef struct ip_addr {
    uint8_t vers;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } addr;
} ip_addr;


//char IP_STR_BUFF[INET6_ADDRSTRLEN];

// Convert an ip struct to a string.
char * iptostr(iphdr *, char *);
int options(unsigned char*, tcp_opt *, unsigned int);

struct timespec time_now(void);

double seconds(struct timespec);
double microseconds(struct timespec);