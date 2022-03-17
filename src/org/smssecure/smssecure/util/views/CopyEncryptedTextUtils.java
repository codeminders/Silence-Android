package org.smssecure.smssecure.util.views;

import android.app.Activity;
import android.content.Context;
import android.text.ClipboardManager;
import android.text.TextUtils;
import android.widget.Toast;

import org.smssecure.smssecure.R;

import java.util.List;

public class CopyEncryptedTextUtils {

    public static void copyEncryptedTextToClipboard(Context context, List<String> result){
        if (result != null) {
            StringBuilder    bodyBuilder = new StringBuilder();
            ClipboardManager clipboard   = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);

            for (String encryptedMessage : result) {
                bodyBuilder.append(encryptedMessage);
            }

            String resultEncodedString = bodyBuilder.toString();

            if (!TextUtils.isEmpty(resultEncodedString))
                clipboard.setText(resultEncodedString);
            Toast.makeText(context,
                    context.getString(R.string.log_submit_activity__copied_to_clipboard),
                    Toast.LENGTH_LONG).show();
        }
    }
}
