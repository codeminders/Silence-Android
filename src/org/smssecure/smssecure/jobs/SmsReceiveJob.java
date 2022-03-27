package org.smssecure.smssecure.jobs;

import android.content.Context;
import android.util.Log;

import org.smssecure.smssecure.ApplicationContext;
import org.smssecure.smssecure.crypto.MasterSecret;
import org.smssecure.smssecure.service.KeyCachingService;
import org.smssecure.smssecure.sms.IncomingTextMessage;
import org.smssecure.smssecure.util.dualsim.DualSimUtil;
import org.whispersystems.jobqueue.JobParameters;

public class SmsReceiveJob extends ContextJob {

  private static final long serialVersionUID = 1L;

  private static final String TAG = SmsReceiveJob.class.getSimpleName();

  protected final Object[] pdus;
  protected final int      subscriptionId;

  public SmsReceiveJob(Context context, Object[] pdus, int subscriptionId) {
    super(context, JobParameters.newBuilder()
            .withPersistence()
            .withWakeLock(true)
            .create());

    Log.w(TAG, "subscriptionId: " + subscriptionId);
    Log.w(TAG, "Found app subscription ID: " + DualSimUtil.getSubscriptionIdFromDeviceSubscriptionId(context, subscriptionId));

    this.pdus           = pdus;
    this.subscriptionId = DualSimUtil.getSubscriptionIdFromDeviceSubscriptionId(context, subscriptionId);
  }

  @Override
  public void onAdded() {}

  @Override
  public void onRun() {
    ReceiveUtils.ReceivedMessage receivedMessage = ReceiveUtils.receiveMessage(context, pdus, subscriptionId, true, null);
    IncomingTextMessage message = receivedMessage.getMessage();
    MasterSecret masterSecret = KeyCachingService.getMasterSecret(context);
    if (masterSecret == null || message.isSecureMessage() || message.isKeyExchange() || message.isEndSession() || message.isXmppExchange()) {
      ApplicationContext.getInstance(context)
                        .getJobManager()
                        .add(new SmsDecryptJob(context, receivedMessage.getMessageId(), masterSecret == null));
    }
  }


  @Override
  public void onCanceled() {

  }

  @Override
  public boolean onShouldRetry(Exception exception) {
    return false;
  }
}
