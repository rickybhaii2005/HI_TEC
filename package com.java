package com.mastertec;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.NetworkInterface;
import java.net.URL;
import java.util.Collections;

public class MainActivity extends AppCompatActivity {

    private static final String SYSTEMSCRIPT_URL = "http://<SYSTEMSCRIPT_DEVICE_IP>:8080/command"; // Replace with systemscript device IP
    private static final String PRIVATE_KEY = "QWERTYUIOP"; // Shared private key for authentication

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button startServiceButton = findViewById(R.id.start_service_button);
        Button stopServiceButton = findViewById(R.id.stop_service_button);
        Button restartServiceButton = findViewById(R.id.restart_service_button);

        startServiceButton.setOnClickListener(v -> sendCommand("START_SERVICE"));
        stopServiceButton.setOnClickListener(v -> sendCommand("STOP_SERVICE"));
        restartServiceButton.setOnClickListener(v -> sendCommand("RESTART_SERVICE"));
    }

    private void sendCommand(String command) {
        new Thread(() -> {
            try {
                URL url = new URL(SYSTEMSCRIPT_URL);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json");

                // Fetch public IP, MAC address, and private IP
                String publicIp = getPublicIp();
                String macAddress = getMacAddress();
                String privateIp = getPrivateIp();

                // Create JSON payload with authentication details
                String jsonPayload = String.format(
                        "{\"command\":\"%s\",\"privateKey\":\"%s\",\"publicIp\":\"%s\",\"macAddress\":\"%s\",\"privateIp\":\"%s\"}",
                        command, PRIVATE_KEY, publicIp, macAddress, privateIp
                );

                try (OutputStream os = connection.getOutputStream()) {
                    os.write(jsonPayload.getBytes());
                    os.flush();
                }

                int responseCode = connection.getResponseCode();
                runOnUiThread(() -> {
                    if (responseCode == HttpURLConnection.HTTP_OK) {
                        Toast.makeText(this, "Command sent: " + command, Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(this, "Failed to send command: " + command, Toast.LENGTH_SHORT).show();
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_SHORT).show());
            }
        }).start();
    }

    private String getPublicIp() {
        try {
            URL url = new URL("https://api.ipify.org");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            return new String(connection.getInputStream().readAllBytes());
        } catch (Exception e) {
            return "Unavailable";
        }
    }

    private String getMacAddress() {
        try {
            for (NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                byte[] mac = networkInterface.getHardwareAddress();
                if (mac != null) {
                    StringBuilder macAddress = new StringBuilder();
                    for (byte b : mac) {
                        macAddress.append(String.format("%02X:", b));
                    }
                    if (macAddress.length() > 0) {
                        macAddress.deleteCharAt(macAddress.length() - 1);
                    }
                    return macAddress.toString();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "Unavailable";
    }

    private String getPrivateIp() {
        try {
            for (NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                for (java.net.InetAddress address : Collections.list(networkInterface.getInetAddresses())) {
                    if (!address.isLoopbackAddress() && address.isSiteLocalAddress()) {
                        return address.getHostAddress();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "Unavailable";
    }
}
