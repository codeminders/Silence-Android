package org.smssecure.smssecure;

import android.app.Activity;

import com.google.zxing.integration.android.IntentIntegrator;

public class QrCodeUtils {
    public static IntentIntegrator getIntentIntegrator(Activity activity) {
      IntentIntegrator intentIntegrator = new IntentIntegrator(activity);
      return intentIntegrator;
    }
}
