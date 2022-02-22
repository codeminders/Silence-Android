package org.smssecure.smssecure.components;

import android.content.Context;
import android.text.InputType;
import android.util.AttributeSet;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.EditTextPreference;

public class EditNumberPreference extends EditTextPreference {
  public EditNumberPreference(@NonNull Context context, @Nullable AttributeSet attrs,
                              int defStyleAttr, int defStyleRes) {
    super(context, attrs, defStyleAttr, defStyleRes);
    initialize();
  }

  public EditNumberPreference(@NonNull Context context, @Nullable AttributeSet attrs,
                              int defStyleAttr) {
    super(context, attrs, defStyleAttr);
    initialize();
  }

  public EditNumberPreference(@NonNull Context context, @Nullable AttributeSet attrs) {
    super(context, attrs);
    initialize();
  }

  public EditNumberPreference(@NonNull Context context) {
    super(context);
    initialize();
  }

  private void initialize() {
    setSummaryProvider((p) -> ((EditNumberPreference) p).getText());
    setOnBindEditTextListener(
            editText -> editText.setInputType(InputType.TYPE_CLASS_NUMBER)
    );
  }
}
