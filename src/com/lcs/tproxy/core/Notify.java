package com.lcs.tproxy.core;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.lcs.tproxy.ui.MainActivity;

public class Notify {

    public static final String CH = "tp_channel";
    public static final int ID = 0x7100;

    public static Notification build(Context c, String title, String text, boolean ongoing) {
        Intent open = new Intent(c, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int flags = Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0;
        PendingIntent pi = PendingIntent.getActivity(c, 1, open, flags);

        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
            NotificationChannel ch = new NotificationChannel(CH, "连接状态", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
            b = new Notification.Builder(c, CH);
        } else {
            b = new Notification.Builder(c);
            b.setPriority(Notification.PRIORITY_LOW);
        }
        b.setContentTitle(title);
        b.setContentText(text);
        b.setSmallIcon(android.R.drawable.stat_sys_download_done);
        b.setContentIntent(pi);
        b.setOngoing(ongoing);
        b.setOnlyAlertOnce(true);
        return b.build();
    }
}
