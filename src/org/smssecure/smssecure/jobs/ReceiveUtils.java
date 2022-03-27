package org.smssecure.smssecure.jobs;

import android.content.Context;
import android.telephony.SmsMessage;
import android.util.Log;
import android.util.Pair;

import org.smssecure.smssecure.crypto.MasterSecret;
import org.smssecure.smssecure.crypto.MasterSecretUtil;
import org.smssecure.smssecure.database.DatabaseFactory;
import org.smssecure.smssecure.database.EncryptingSmsDatabase;
import org.smssecure.smssecure.notifications.MessageNotifier;
import org.smssecure.smssecure.protocol.WirePrefix;
import org.smssecure.smssecure.recipients.RecipientFactory;
import org.smssecure.smssecure.recipients.Recipients;
import org.smssecure.smssecure.service.KeyCachingService;
import org.smssecure.smssecure.sms.IncomingTextMessage;
import org.smssecure.smssecure.sms.MultipartSmsMessageHandler;
import org.whispersystems.libsignal.util.guava.Optional;

import java.util.LinkedList;
import java.util.List;

public abstract class ReceiveUtils {

  private static final String TAG = ReceiveUtils.class.getSimpleName();

  private static MultipartSmsMessageHandler multipartMessageHandler = new MultipartSmsMessageHandler();

  public static ReceivedMessage receiveMessage(Context context, Object[] pdus, int subscriptionId, boolean isSms, String sender) {
    Log.w(ReceiveUtils.TAG, "Running for subscriptionId " + subscriptionId);
    MasterSecret masterSecret = KeyCachingService.getMasterSecret(context);
    Optional<IncomingTextMessage> message = assembleMessageFragments(isSms, pdus, subscriptionId, masterSecret, sender);

    ReceivedMessage receivedMessage = null;
    if (message.isPresent() && !isBlocked(context, message.get())) {
      Pair<Long, Long> messageAndThreadId = storeMessage(context, message.get());

      IncomingTextMessage incomingTextMessage = message.get();
      if (incomingTextMessage.isReceivedWhenLocked() ||
         (!incomingTextMessage.isSecureMessage()     &&
          !incomingTextMessage.isKeyExchange()       &&
          !incomingTextMessage.isXmppExchange()))
      {
        MessageNotifier.updateNotification(context, masterSecret, messageAndThreadId.second);
      }

      if (incomingTextMessage.getSender() != null) {
        Recipients recipients = RecipientFactory.getRecipientsFromString(context, incomingTextMessage.getSender(), false);
        DatabaseFactory.getRecipientPreferenceDatabase(context)
                       .setDefaultSubscriptionId(recipients, incomingTextMessage.getSubscriptionId());
      }
      receivedMessage = new ReceivedMessage(messageAndThreadId.second, messageAndThreadId.first, incomingTextMessage);
    } else if (message.isPresent()) {
      Log.w(TAG, "*** Received blocked SMS, ignoring...");
    }
    return receivedMessage;
  }


  private static boolean isBlocked(Context context, IncomingTextMessage message) {
    if (message.getSender() != null) {
      Recipients recipients = RecipientFactory.getRecipientsFromString(context, message.getSender(), false);
      return recipients.isBlocked();
    }

    return false;
  }

  private static Pair<Long, Long> storeMessage(Context context, IncomingTextMessage message) {
    EncryptingSmsDatabase database     = DatabaseFactory.getEncryptingSmsDatabase(context);
    MasterSecret          masterSecret = KeyCachingService.getMasterSecret(context);

    Pair<Long, Long> messageAndThreadId;

    if (message.isSecureMessage()) {
      messageAndThreadId = database.insertMessageInbox((MasterSecret)null, message);
    } else if (masterSecret == null) {
      messageAndThreadId = database.insertMessageInbox(MasterSecretUtil.getAsymmetricMasterSecret(context, null), message);
    } else {
      messageAndThreadId = database.insertMessageInbox(masterSecret, message);
    }

    return messageAndThreadId;
  }

  private static Optional<IncomingTextMessage> assembleMessageFragments(boolean isSms, Object[] pdus, int subscriptionId, MasterSecret masterSecret, String sender)
  {
    List<IncomingTextMessage> messages;
    if (isSms) {
      messages = getIncomingSmsMessages(pdus, subscriptionId, masterSecret);
    } else {
      messages = getIncomingTextMessages(pdus,subscriptionId, masterSecret, sender);
    }

    if (messages.isEmpty()) {
      return Optional.absent();
    }

    IncomingTextMessage message = new IncomingTextMessage(messages);

    if (WirePrefix.isPrefixedMessage(message.getMessageBody())) {
      return Optional.fromNullable(multipartMessageHandler.processPotentialMultipartMessage(message));
    } else {
      return Optional.of(message);
    }
  }

  protected static List<IncomingTextMessage> getIncomingSmsMessages(Object[] pdus, int subscriptionId, MasterSecret masterSecret) {
    List<IncomingTextMessage> messages = new LinkedList<>();

    for (Object pdu : pdus) {
      SmsMessage msg = SmsMessage.createFromPdu((byte[]) pdu);
      if (msg != null){
        messages.add(new IncomingTextMessage(msg, subscriptionId, masterSecret == null));
      }
    }
    return messages;
  }

  private static List<IncomingTextMessage> getIncomingTextMessages(Object[] pdus, int subscriptionId, MasterSecret masterSecret, String sender) {
    List<IncomingTextMessage> messages = new LinkedList<>();

    for (Object pdu : pdus) {
      IncomingTextMessage txtMsg = new IncomingTextMessage(sender, 1, System.currentTimeMillis(), (String) pdu, subscriptionId);
      messages.add(txtMsg);
    }
    return messages;
  }

  public static class ReceivedMessage {
    private final long threadId;
    private final long messageId;
    private final IncomingTextMessage message;

    public ReceivedMessage(long threadId, long messageId, IncomingTextMessage message) {
      this.threadId = threadId;
      this.messageId = messageId;
      this.message = message;
    }

    public long getThreadId() {
      return threadId;
    }

    public long getMessageId() {
      return messageId;
    }

    public IncomingTextMessage getMessage() {
      return message;
    }
  }

}
