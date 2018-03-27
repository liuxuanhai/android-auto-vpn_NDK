package cl.niclabs.vpnpassiveping;

import android.app.Activity;
import android.content.Intent;
import android.content.res.AssetManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends Activity {
    private static final String TAG = "MainActivity";

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        checkAbi();
    }

    private void checkAbi() {
        String abi;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            abi = Build.SUPPORTED_ABIS[0];
        } else {
            //noinspection deprecation
            abi = Build.CPU_ABI;
        }

        Log.d(TAG, abi);

        AssetManager assetManager = getAssets();
        try {
            InputStream in = assetManager.open(abi + "/auto_vpn");

            OutputStream out = getApplicationContext().openFileOutput("auto_vpn", MODE_PRIVATE);
            long size = 0;
            int nRead;
            byte[] buff = new byte[1024];
            while ((nRead = in.read(buff)) != -1) {
                out.write(buff, 0, nRead);
                size += nRead;
            }
            out.flush();
            out.close();
            Log.d(TAG, "Copy success: "+ size + " bytes");
            File execFile = new File(getApplicationContext().getFilesDir() + "/auto_vpn");
            execFile.setExecutable(true);

            Process p = Runtime.getRuntime().exec("su");

            DataOutputStream dos = new DataOutputStream(p.getOutputStream());
            dos.writeBytes("cd " + getApplicationContext().getFilesDir() + "\n");
            //dos.writeBytes("./auto_vpn\n");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void onClickButton(View view) {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, 0);
        } else {
            onActivityResult(0, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (result == RESULT_OK) {
            Intent intent = new Intent(this, AutoVpnService.class);
            startService(intent);
        }
    }

}
