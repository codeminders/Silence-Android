package org.smssecure.smssecure.jobs;

import android.content.Context;
import android.util.Log;

import org.smssecure.smssecure.crypto.MasterSecret;
import org.smssecure.smssecure.crypto.TextMessageDecryptUtils;
import org.smssecure.smssecure.database.NoSuchMessageException;
import org.smssecure.smssecure.jobs.requirements.MasterSecretRequirement;
import org.whispersystems.jobqueue.JobParameters;

public class SmsDecryptJob extends MasterSecretJob {

  private static final String TAG = SmsDecryptJob.class.getSimpleName();

  private final long    messageId;
  private final boolean manualOverride;
  private final Boolean isReceivedWhenLocked;

  public SmsDecryptJob(Context context, long messageId, boolean manualOverride, boolean isReceivedWhenLocked) {
    super(context, JobParameters.newBuilder()
                                .withPersistence()
                                .withRequirement(new MasterSecretRequirement(context))
                                .create());

    this.messageId            = messageId;
    this.manualOverride       = manualOverride;
    this.isReceivedWhenLocked = isReceivedWhenLocked;

    Log.w(TAG, "manualOverride: " + manualOverride);
    Log.w(TAG, "isReceivedWhenLocked: " + isReceivedWhenLocked);
  }

  public SmsDecryptJob(Context context, long messageId) {
    this(context, messageId, false, false);
  }

  public SmsDecryptJob(Context context, long messageId, boolean isReceivedWhenLocked) {
    this(context, messageId, false, isReceivedWhenLocked);
  }

  @Override
  public void onAdded() {}

  @Override
  public void onRun(MasterSecret masterSecret) throws NoSuchMessageException {
    TextMessageDecryptUtils.decryptMessage(context, masterSecret, messageId, isReceivedWhenLocked, manualOverride);
  }

  @Override
  public boolean onShouldRetryThrowable(Exception exception) {
    return false;
  }

  @Override
  public void onCanceled() {
    // TODO
  }

}
