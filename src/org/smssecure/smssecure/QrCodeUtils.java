package org.smssecure.smssecure;

import android.app.Activity;

import com.google.zxing.integration.android.IntentIntegrator;

public class QrCodeUtils {
    public static IntentIntegrator getIntentIntegrator(Activity activity) {
      IntentIntegrator intentIntegrator = new IntentIntegrator(activity);
      intentIntegrator.setButtonYesByID(R.string.yes);
      intentIntegrator.setButtonNoByID(R.string.no);
      intentIntegrator.setTitleByID(R.string.KeyScanningActivity_install_barcode_Scanner);
      intentIntegrator.setMessageByID(R.string.KeyScanningActivity_this_application_requires_barcode_scanner_would_you_like_to_install_it);
      return intentIntegrator;
    }
}
