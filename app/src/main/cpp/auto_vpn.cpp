#include <sys/signalfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/epoll.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
int receive_packet(unsigned char * pkt); 

/* Global variables */
char *uds_path = "/data/data/cl.niclabs.vpnpassiveping/sock_path"; /* unix domain socket path*/
int uds_fd = -1;     /* listening descriptor */


/* Setup server to establish a Unix Domain Socket */
int setup_listener(void) {
    struct sockaddr_un addr;

    if ((uds_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("Unix Domain Socket failed");
        exit(EXIT_FAILURE);
    }

    /* Bind Unix Domain Socket with local path */
    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;

    strncpy(addr.sun_path, uds_path, sizeof(addr.sun_path)-1);
    unlink(uds_path);

    if (bind(uds_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind Unix Domain Socket failed");
        exit(EXIT_FAILURE);
    }

    if (listen(uds_fd, 5) < 0) {
        perror("Listen Unix Domain Socket failed");
        exit(EXIT_FAILURE);
    }

    /* UNIX domain sockets need to be mode 777 on 4.3 */
    chmod(addr.sun_path, 0777);
    return 1;
}

/* Accept unix domain socket client */
int handle_client(void) {
    int fd;

    if ((fd = accept(uds_fd, NULL, NULL)) < 0) {
        perror("Accept Unix Domain Socket failed");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Accepted client fd: %d\n", fd);
    return fd;
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


int start_VPN(int fd, int sd, int tcp_sd) {
    unsigned char buffer[65536];

    int bytes_read;

    while(1){
        int i;
        for(i=0; i<100; i++){
            bytes_read = read(fd, buffer, 65536);

            if (bytes_read <= 0)
                break;

            receive_packet(buffer);
            struct ip *iphdr = (struct ip*)buffer;

            struct sockaddr_in sin;
            memset (&sin, 0, sizeof (struct sockaddr_in));
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = iphdr->ip_dst.s_addr;

            if (sendto (sd, buffer, bytes_read, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)
                break;
        }

        for(i=0; i<100; i++){
            int bytes_read;
            struct sockaddr saddr;
            int saddr_len = sizeof(saddr);

            bytes_read = recvfrom(tcp_sd, buffer, 65536, MSG_DONTWAIT, &saddr, (socklen_t *)&saddr_len);

            if (bytes_read <= 0)
                break;
            receive_packet(buffer);

            if (write(fd, buffer, bytes_read) < 0)
                break;
        }
    }

    close(fd); /* close the passed descriptor */
    return 1;
}

/* Receive a file descriptor from client fd on Unix Domain Socket */
int receive_fd(int fd) {
    int passed_fd = -1;
    char buf[1000];
    struct msghdr msg;
    struct iovec iov[1];
    ssize_t n;
    union {
        struct cmsghdr cm;
        char     control[CMSG_SPACE(sizeof (int))];
    } control_un;
    struct cmsghdr  *cmptr;
    msg.msg_control  = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    if ((n = recvmsg(fd, &msg, 0)) <= 0)
        return n;
    if ((cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
        cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmptr->cmsg_level != SOL_SOCKET)
            fprintf(stderr, "control level != SOL_SOCKET\n");
        if (cmptr->cmsg_type != SCM_RIGHTS)
            fprintf(stderr, "control type != SCM_RIGHTS\n");
        passed_fd = (*(int *) CMSG_DATA(cmptr));
        fprintf(stderr, "passed fd %d\n", passed_fd);
    }
    else
        passed_fd = -1;           /* descriptor was not passed */
    fprintf(stderr, "passed fd %d\n", passed_fd);

    return passed_fd;
}

int main(int argc, char *argv[]) {
    const int on = 1;
    setup_listener();

    int client = handle_client();

    int passed_fd = receive_fd(client);

    // Close Unix Domain Socket
    if (uds_fd != -1) close(uds_fd);

    // Submit request for a raw socket descriptor.
    int sd;
    if ((sd = socket (AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW)) < 0) {
        perror ("socket() failed ");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr,"Raw Socket descriptor: %d\n", sd);

    // Set flag so socket expects us to provide IPv4 header.
    /*if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
      perror ("setsockopt() failed to set IP_HDRINCL ");
      exit (EXIT_FAILURE);
    }*/

    protect(sd);

    int tcp_sd;
    if ((tcp_sd = socket (AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP)) < 0) {
        perror ("socket() failed ");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr,"TCP Raw Socket descriptor: %d\n", tcp_sd);
    protect(tcp_sd);

    fprintf(stderr,"start utilize\n");
    start_VPN(passed_fd, sd, tcp_sd);
    fprintf(stderr,"end utilize\n");

    if (uds_fd != -1) close(uds_fd);
    return 0;
}
