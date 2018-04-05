package cl.niclabs.vpnpassiveping;

import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import java.io.DataOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.util.Enumeration;

public class AutoVpnService extends VpnService implements Handler.Callback, Runnable {
    private static final String TAG = "AutoVpnService";

    private Handler mHandler;
    private Thread mThread;

    private ParcelFileDescriptor mInterface;

    /*public native int startVPN(FileDescriptor fileDescriptor);
    static {
        System.loadLibrary("vpn_jni");
    }*/

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // The handler is only used to show messages.
        if (mHandler == null) {
            mHandler = new Handler(this);
        }

        // Stop the previous session by interrupting the thread.
        if (mThread != null) {
            mThread.interrupt();
        }

        // Start a new session by creating a new thread.
        mThread = new Thread(this, TAG);
        mThread.start();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (mThread != null) {
            mThread.interrupt();
        }
    }

    @Override
    public boolean handleMessage(Message message) {
        if (message != null) {
            Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        }
        return true;
    }

    @Override
    public synchronized void run() {
        try {
            Log.i(TAG, "Starting");
            runVPN();

        } catch (Exception e) {
            Log.e(TAG, "Got " + e.toString());
        }
    }

    private boolean runVPN() throws Exception {
        boolean connected = false;
        configure();
        //int rc = startVPN(mInterface.getFileDescriptor());
        //Log.d(TAG, "start VPN: " + rc);
        return connected;
    }

    private void configure() {
        Builder builder = new Builder();
        builder.setMtu(16000);
        boolean v4State = false;
        boolean v6State = false;
        boolean v6support = false;
        try {
            String address = getLocalIpAddress(false); //IPv4 Address
            if (address != null) {
                builder.addAddress(address, 32);
                builder.addDnsServer("8.8.8.8");
                builder.addRoute("0.0.0.0", 0);
                v4State = true;
            }

            try {
                InetSocketAddress testSocketAddress = new InetSocketAddress(Inet6Address.getByName("2607:f8b0:4010:800::1002"), 80);
                Socket test_socket = new Socket();
                test_socket.connect(testSocketAddress, 50);
                test_socket.close();
                v6support = true;
            } catch (SocketException e2) {
                v6support = false;
            } catch (Exception e3) {
                v6support = true;
            }
            address = getLocalIpAddress(true);

            if (!v6support || address == null || Build.VERSION.SDK_INT <= 19) {
                v6support = false;
                try {
                    this.mInterface.close();
                } catch (Exception e4) {
                }
                Log.d(TAG, address + v4State);
                if (v4State) {
                    Log.i(TAG, "IPv4 supported");
                    this.mInterface = builder.establish();
                } else {
                    Log.i(TAG, "Couldn't get v4 address. v6 not available, or not supported on your phone");
                }
                if (this.mInterface == null) {
                    Log.e(TAG, "Error establishing VPN connection. VPN interface is null");
                    stopSelf();
                }
                return;
            }
            Log.i(TAG, "Defining IP address : " + address);
            builder.addAddress(address, 64);
            builder.addDnsServer("2001:4860:4860::8888");
            builder.addRoute("0::0", 0);
            v6State = true;
            this.mInterface.close();
            if (v4State) {
            }
            Log.i(TAG, "IPv4 and IPv6 supported");
            this.mInterface = builder.establish();
            if (this.mInterface != null) {
                return;
            }
            Log.e(TAG, "Error establishing VPN connection. VPN interface is null");
            stopSelf();
        } catch (Exception e1) {
            Log.e(TAG, "Error creating localhost: " + e1.getMessage(), e1);
        }
    }

    public static String getLocalIpAddress(boolean v6) {
        try {
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            while (en.hasMoreElements()) {
                Enumeration<InetAddress> enumIpAddr = ((NetworkInterface) en.nextElement()).getInetAddresses();
                while (enumIpAddr.hasMoreElements()) {
                    InetAddress inetAddress = (InetAddress) enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress() && !inetAddress.isAnyLocalAddress() && !inetAddress.isLinkLocalAddress() && !inetAddress.isMulticastAddress() && inetAddress.getHostAddress().toString() != null && isV6(inetAddress) == v6) {
                        return inetAddress.getHostAddress().toString();
                    }
                }
            }
        } catch (Exception ex) {
            Log.e(TAG, ex.getMessage(), ex);
        }
        return null;
    }

    public static boolean isV6(InetAddress domainIP) {
        if (domainIP instanceof Inet4Address) {
            return false;
        }
        return true;
    }
}
