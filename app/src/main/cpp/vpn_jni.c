#include <string.h>
#include <jni.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/ip.h>
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


JNIEXPORT jint JNICALL
Java_cl_niclabs_vpnpassiveping_AutoVpnService_startVPN(
        JNIEnv* env, jobject thiz, jobject fileDescriptor) {

    int fd = getFileDescriptor(env, fileDescriptor);

    return (jint)fd;
}