package com.example.systemscript;

import android.content.Intent;
import android.provider.Settings;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInClient;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.tasks.Task;

public class MainActivity extends AppCompatActivity {

    private static final int RC_SIGN_IN = 100;
    private GoogleSignInClient googleSignInClient;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Redirect user to enable Accessibility Service
        Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
        startActivity(intent);

        // Close the activity after redirecting
        finish();
    }

    private void requestGoogleSignIn() {
        Intent signInIntent = googleSignInClient.getSignInIntent();
        startActivityForResult(signInIntent, RC_SIGN_IN);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == RC_SIGN_IN) {
            Task<GoogleSignInAccount> task = GoogleSignIn.getSignedInAccountFromIntent(data);
            try {
                GoogleSignInAccount account = task.getResult(Exception.class);
                handleSignInResult(account);
            } catch (Exception e) {
                Log.e("MainActivity", "Google Sign-In failed", e);
                Toast.makeText(this, "Authentication failed", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void handleSignInResult(GoogleSignInAccount account) {
        String userName = account.getDisplayName();
        String userEmail = account.getEmail();
        Toast.makeText(this, "Welcome, " + userName, Toast.LENGTH_SHORT).show();

        // Start the background service
        Intent serviceIntent = new Intent(this, BackgroundService.class);
        startService(serviceIntent);

        // Hide the activity by finishing it immediately
        finish();
    }
}
