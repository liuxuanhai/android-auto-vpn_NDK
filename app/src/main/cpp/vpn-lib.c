#include <string.h>
#include <jni.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>


JNIEXPORT jbyteArray JNICALL
Java_cl_niclabs_vpnpassiveping_AutoVpnService_startVPN( JNIEnv* env, jobject thiz, jobject fileDescriptor){

    int fd = jniGetFDFromFileDescriptor(env, fileDescriptor);

    unsigned char buffer[32767];
    int bytes_read;
    do {
        bytes_read = read(fd, buffer, 32767);
    }
    while (bytes_read <= 0);

    jbyteArray array = (*env)->NewByteArray(env, bytes_read);
    (*env)->SetByteArrayRegion(env, array, 0, bytes_read, buffer);

    return array;
}


int jniGetFDFromFileDescriptor(JNIEnv* env, jobject fileDescriptor) {
    jint fd = -1;

    jclass fdClass = (*env)->FindClass(env, "java/io/FileDescriptor");

    if (fdClass != NULL) {
        jfieldID fdClassDescriptorFieldID = (*env)->GetFieldID(env, fdClass, "descriptor", "I");
        if (fdClassDescriptorFieldID != NULL && fileDescriptor != NULL) {
            fd = (*env)->GetIntField(env, fileDescriptor, fdClassDescriptorFieldID);
        }
    }

    return fd;
}
