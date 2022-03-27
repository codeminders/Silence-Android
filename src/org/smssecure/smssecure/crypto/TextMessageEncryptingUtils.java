package org.smssecure.smssecure.crypto;

import android.content.Context;
import android.telephony.SmsManager;
import android.util.Log;

import org.smssecure.smssecure.crypto.storage.SilenceSessionStore;
import org.smssecure.smssecure.crypto.storage.SilenceSignalProtocolStore;
import org.smssecure.smssecure.database.DatabaseFactory;
import org.smssecure.smssecure.database.EncryptingSmsDatabase;
import org.smssecure.smssecure.database.NoSuchMessageException;
import org.smssecure.smssecure.database.model.SmsMessageRecord;
import org.smssecure.smssecure.jobs.ReceiveUtils;
import org.smssecure.smssecure.service.KeyCachingService;
import org.smssecure.smssecure.sms.IncomingTextMessage;
import org.smssecure.smssecure.sms.MessageSender;
import org.smssecure.smssecure.sms.MultipartSmsMessageHandler;
import org.smssecure.smssecure.sms.OutgoingTextMessage;
import org.smssecure.smssecure.transport.UndeliverableMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.state.SessionStore;

import java.util.ArrayList;
import java.util.List;

public class TextMessageEncryptingUtils {

    private static final String TAG = TextMessageEncryptingUtils.class.getSimpleName();

    public static EncryptedMultipartMessage decrypt(final Context context, String encrypted, int subscriptionId, String sender)
            throws NoSuchMessageException, UntrustedIdentityException, UndeliverableMessageException {
        String[] encryptedArr = new String[] { encrypted };
        ReceiveUtils.ReceivedMessage receivedMessage = ReceiveUtils.receiveMessage(context, encryptedArr, subscriptionId, false, sender);
        MasterSecret masterSecret = KeyCachingService.getMasterSecret(context);
        IncomingTextMessage message = receivedMessage.getMessage();

        if (masterSecret == null || message.isSecureMessage() || message.isKeyExchange() || message.isEndSession() || message.isXmppExchange()) {
            OutgoingTextMessage outgoingTextMessage = TextMessageDecryptUtils.decryptMessage(context, masterSecret, receivedMessage.getMessageId(), false, false, false);
            if (outgoingTextMessage != null) {
                return MessageSender.encrypt(context, masterSecret, outgoingTextMessage, receivedMessage.getThreadId());
            }
        }
        return null;
    }

    public static List<String> encrypt(final Context context, final MasterSecret masterSecret, final long messageId)
            throws NoSuchMessageException, UntrustedIdentityException, UndeliverableMessageException
    {
        EncryptingSmsDatabase database = DatabaseFactory.getEncryptingSmsDatabase(context);
        SmsMessageRecord record   = database.getMessage(masterSecret, messageId);

        ArrayList<String> encryptMultipartText = encryptMultipartText(masterSecret, record, context);

        if (record.isEndSession()) {
            Log.w(TAG, "Ending session...");
            SessionStore sessionStore = new SilenceSessionStore(context, masterSecret, record.getSubscriptionId());
            sessionStore.deleteAllSessions(record.getIndividualRecipient().getNumber());
            SecurityEvent.broadcastSecurityUpdateEvent(context, record.getThreadId());
        }
        return encryptMultipartText;
    }

    public static ArrayList<String> encryptMultipartText(MasterSecret masterSecret, SmsMessageRecord message,
                                                         Context context)
            throws UndeliverableMessageException, UntrustedIdentityException
    {
      ArrayList<String> messages;
      if (message.isSecure() || message.isKeyExchange() || message.isEndSession()) {
        MultipartSmsMessageHandler multipartMessageHandler = new MultipartSmsMessageHandler();
        OutgoingTextMessage transportMessage        = OutgoingTextMessage.from(message);

        if (!message.isKeyExchange()) {
          transportMessage = getAsymmetricEncrypt(masterSecret, transportMessage, context);
        }

        messages = SmsManager.getDefault().divideMessage(multipartMessageHandler.getEncodedMessage(transportMessage));
      } else {
        messages = SmsManager.getDefault().divideMessage(message.getBody().getBody());
      }
      return messages;
    }

    public static OutgoingTextMessage getAsymmetricEncrypt(MasterSecret masterSecret,
                                                             OutgoingTextMessage message, Context context)
        throws UndeliverableMessageException, UntrustedIdentityException

    {
      try {
        return new SmsCipher(new SilenceSignalProtocolStore(context, masterSecret, message.getSubscriptionId())).encrypt(message);
      } catch (NoSessionException e) {
        throw new UndeliverableMessageException(e);
      }
    }

}
