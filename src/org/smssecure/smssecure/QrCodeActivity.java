package org.smssecure.smssecure;

import android.app.Activity;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.Toast;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.journeyapps.barcodescanner.BarcodeEncoder;

import org.smssecure.smssecure.crypto.MasterSecret;
import org.smssecure.smssecure.transport.UndeliverableMessageException;
import org.smssecure.smssecure.util.DynamicLanguage;
import org.smssecure.smssecure.util.DynamicTheme;
import org.smssecure.smssecure.util.ViewUtil;

import androidx.annotation.NonNull;

public class QrCodeActivity extends PassphraseRequiredActionBarActivity {

    private static final String TAG = QrCodeActivity.class.getSimpleName();
    public static final String KEY_EXCHANGE = "KEY_EXCHANGE";
    public static final String SHOW_NEXT = "SHOW_NEXT";

    private final DynamicTheme dynamicTheme    = new DynamicTheme   ();
    private final DynamicLanguage dynamicLanguage = new DynamicLanguage();



    @Override
    protected void onPreCreate() {
        dynamicTheme.onCreate(this);
        dynamicLanguage.onCreate(this);
    }

    @Override
    protected void onCreate(Bundle state, @NonNull MasterSecret masterSecret) {
        setContentView(R.layout.qr_code_activity);

        final Button nextButton = ViewUtil.findById(this, R.id.qr_code_next_button);
        final Button cancelButton = ViewUtil.findById(this, R.id.qr_code_cancel_button);
        final ImageView qrCodeView = ViewUtil.findById(this, R.id.qr_code_view);
        String key = getIntent().getStringExtra(KEY_EXCHANGE);
        boolean showNext = getIntent().getBooleanExtra(SHOW_NEXT, true);
        Bitmap qrCode = generateQrCode(key);
        if (qrCode == null) onBackPressed();

        qrCodeView.setImageBitmap(qrCode);

        if (showNext) {
            nextButton.setOnClickListener(view -> {
                setResult(Activity.RESULT_OK);
                onBackPressed();
            });
        } else {
            nextButton.setVisibility(View.GONE);
        }

        cancelButton.setOnClickListener(view -> {
            setResult(Activity.RESULT_CANCELED);
            onBackPressed();
        });

    }

    private Bitmap generateQrCode(String text) {

        MultiFormatWriter multiFormatWriter = new MultiFormatWriter();
        try {
            BitMatrix bitMatrix = multiFormatWriter.encode(text, BarcodeFormat.QR_CODE, 1000, 1000);
            BarcodeEncoder barcodeEncoder = new BarcodeEncoder();
            return barcodeEncoder.createBitmap(bitMatrix);

        } catch (WriterException e) {
            Log.e(TAG, "Cannot generate barcode", e);
            Toast.makeText(QrCodeActivity.this, "Cannot generate barcode", Toast.LENGTH_LONG);
            return null;
        }

    }


}
