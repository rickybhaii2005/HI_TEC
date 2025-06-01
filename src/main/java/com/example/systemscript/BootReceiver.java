package com.example.systemscript;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            // Start the BackgroundService
            Intent serviceIntent = new Intent(context, BackgroundService.class);
            context.startService(serviceIntent);

            // Log the action
            Log.d("BootReceiver", "Device rebooted. BackgroundService started.");
        }
    }
}
