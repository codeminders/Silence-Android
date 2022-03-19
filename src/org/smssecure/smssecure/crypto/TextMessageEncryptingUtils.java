package org.smssecure.smssecure.crypto;

import android.content.Context;
import android.telephony.SmsManager;

import org.smssecure.smssecure.ApplicationContext;
import org.smssecure.smssecure.crypto.storage.SilenceSignalProtocolStore;
import org.smssecure.smssecure.database.DatabaseFactory;
import org.smssecure.smssecure.database.EncryptingSmsDatabase;
import org.smssecure.smssecure.database.NoSuchMessageException;
import org.smssecure.smssecure.database.model.SmsMessageRecord;
import org.smssecure.smssecure.jobs.TextReceiveJob;
import org.smssecure.smssecure.sms.MultipartSmsMessageHandler;
import org.smssecure.smssecure.sms.OutgoingTextMessage;
import org.smssecure.smssecure.transport.UndeliverableMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.UntrustedIdentityException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class TextMessageEncryptingUtils {

    public static void decrypt(final Context context, String encrypted, int subscriptionId, String sender)
    {
        String[] encryptedArr = new String[] { encrypted };
        ApplicationContext.getInstance(context).getJobManager()
                .add(new TextReceiveJob(context, encryptedArr, subscriptionId, sender));
    }

    public static List<String> encrypt(final Context context, final MasterSecret masterSecret, final long messageId)
            throws NoSuchMessageException, UntrustedIdentityException, UndeliverableMessageException
    {
        EncryptingSmsDatabase database = DatabaseFactory.getEncryptingSmsDatabase(context);
        SmsMessageRecord record   = database.getMessage(masterSecret, messageId);

        return encryptMultipartText(masterSecret, record, context);
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
