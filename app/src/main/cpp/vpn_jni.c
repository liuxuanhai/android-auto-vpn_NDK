#include <string.h>
#include <jni.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <android/log.h>

char *server_path = "/data/data/cl.niclabs.vpnpassiveping/sock_path";
int uds_fd = -1;

/* Get file descriptor number from Java object FileDescriptor */
int getFileDescriptor(JNIEnv* env, jobject fileDescriptor) {
    jint fd = -1;

    jclass fdClass = (*env)->FindClass(env, "java/io/FileDescriptor");

    if (fdClass != NULL) {
        jfieldID fdClassDescriptorFieldID = (*env)->GetFieldID(env, fdClass, "descriptor", "I");
        if (fdClassDescriptorFieldID != NULL && fileDescriptor != NULL) {
            fd = (*env)->GetIntField(env, fileDescriptor, fdClassDescriptorFieldID);
        }
    }
    __android_log_print(ANDROID_LOG_ERROR, "JNI ","VPN fd: %d", fd);

    return fd;
}



/* Client function to connect to a Unix Domain Socket */
int open_socket(void) {
    struct sockaddr_un server_addr;
    int sc, rc = -1;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, server_path, sizeof(server_addr.sun_path)-1);

    uds_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (uds_fd == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "JNI ","socket: %s\n", strerror(errno));
        goto done;
    }

    sc = connect(uds_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));

    if (sc == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "JNI ","connect: %s\n", strerror(errno));
        goto done;
    }

    rc = 0;

    done:
    return rc;
}

/* pass fd over unix domain socket uds_fd */
int pass_fd(int fd, int sock_fd) {
    struct msghdr hdr;
    struct iovec iov;
    int rc = -1, sc;

    /* Allocate a char array of suitable size to hold the ancillary data.
       However, since this buffer is in reality a 'struct cmsghdr', use a
       union to ensure that it is aligned as required for that structure. */
    union {
        struct cmsghdr cmh;
        char   control[CMSG_SPACE(sizeof(int))]; /* sized to hold an fd (int) */
    } control_un;
    memset(&control_un, 0, sizeof(control_un));

    /* we have to transmit at least 1 byte to send ancillary data */
    char unused = '*';
    iov.iov_base = &unused;
    iov.iov_len = sizeof(unused);

    /* point to iov to transmit */
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    /* no dest address; socket is connected */
    hdr.msg_name = NULL;
    hdr.msg_namelen = 0;
    /* control is where specificy SCM_RIGHTS (fd pass)*/
    hdr.msg_control = control_un.control;
    hdr.msg_controllen = sizeof(control_un.control);

    /* poke into the union which is now inside hdr */
    struct cmsghdr *hp;
    hp = CMSG_FIRSTHDR(&hdr);
    hp->cmsg_len = CMSG_LEN(sizeof(int));
    hp->cmsg_level = SOL_SOCKET;
    hp->cmsg_type = SCM_RIGHTS;
    *((int *) CMSG_DATA(hp)) = fd;

    sc = sendmsg(sock_fd, &hdr, 0);
    if (sc < 0) {
        __android_log_print(ANDROID_LOG_ERROR, "JNI ","sendmsg: %s\n", strerror(errno));
        goto done;
    }

    rc = 0;

    done:
    return rc;
}

JNIEXPORT jint JNICALL
Java_cl_niclabs_vpnpassiveping_AutoVpnService_startVPN(
        JNIEnv* env, jobject thiz, jobject fileDescriptor) {

    int fd = getFileDescriptor(env, fileDescriptor);

    /* open the unix domain socket (client end) */
    if (open_socket() < 0) return -3;

    /* pass descriptor fd to peer over socket */
    if (pass_fd(fd, uds_fd) < 0) return -4;

    if (uds_fd != -1) close(uds_fd);

    return (jint)fd;
}
