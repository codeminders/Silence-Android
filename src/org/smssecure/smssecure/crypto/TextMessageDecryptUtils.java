package org.smssecure.smssecure.crypto;

import android.content.Context;
import android.util.Log;

import org.smssecure.smssecure.crypto.storage.SilenceSignalProtocolStore;
import org.smssecure.smssecure.database.DatabaseFactory;
import org.smssecure.smssecure.database.EncryptingSmsDatabase;
import org.smssecure.smssecure.database.NoSuchMessageException;
import org.smssecure.smssecure.database.model.SmsMessageRecord;
import org.smssecure.smssecure.notifications.MessageNotifier;
import org.smssecure.smssecure.recipients.RecipientFactory;
import org.smssecure.smssecure.recipients.Recipients;
import org.smssecure.smssecure.sms.IncomingEncryptedMessage;
import org.smssecure.smssecure.sms.IncomingEndSessionMessage;
import org.smssecure.smssecure.sms.IncomingKeyExchangeMessage;
import org.smssecure.smssecure.sms.IncomingPreKeyBundleMessage;
import org.smssecure.smssecure.sms.IncomingTextMessage;
import org.smssecure.smssecure.sms.IncomingXmppExchangeMessage;
import org.smssecure.smssecure.sms.MessageSender;
import org.smssecure.smssecure.sms.OutgoingKeyExchangeMessage;
import org.smssecure.smssecure.sms.OutgoingTextMessage;
import org.smssecure.smssecure.util.SilencePreferences;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.StaleKeyExchangeException;
import org.whispersystems.libsignal.UntrustedIdentityException;

import java.io.IOException;

public class TextMessageDecryptUtils {
    private static final String TAG = TextMessageDecryptUtils.class.getSimpleName();

    public static OutgoingTextMessage decryptMessage(Context context, MasterSecret masterSecret, long messageId,
                                                     boolean isReceivedWhenLocked, boolean manualOverride, boolean isSms)
            throws NoSuchMessageException {
        EncryptingSmsDatabase database = DatabaseFactory.getEncryptingSmsDatabase(context);

        OutgoingTextMessage response = null;
        try {
            SmsMessageRecord record = database.getMessage(masterSecret, messageId);
            IncomingTextMessage message = createIncomingTextMessage(context, masterSecret, record);

            messageId = record.getId();
            long threadId = record.getThreadId();

            if (message.isSecureMessage())
                handleSecureMessage(context, masterSecret, messageId, threadId, message);
            else if (message.isPreKeyBundle())
                handlePreKeySignalMessage(context, masterSecret, messageId, threadId, (IncomingPreKeyBundleMessage) message);
            else if (message.isKeyExchange())
                response= handleKeyExchangeMessage(context, masterSecret, messageId, threadId, (IncomingKeyExchangeMessage) message, manualOverride, isSms);
            else if (message.isEndSession())
                handleSecureMessage(context, masterSecret, messageId, threadId, message);
            else if (message.isXmppExchange())
                handleXmppExchangeMessage(context, masterSecret, messageId, threadId, (IncomingXmppExchangeMessage) message);
            else database.updateMessageBody(masterSecret, messageId, message.getMessageBody());

            if (!isReceivedWhenLocked) {
                MessageNotifier.updateNotification(context, masterSecret, threadId);
            } else {
                MessageNotifier.updateNotification(context, masterSecret);
            }
        } catch (LegacyMessageException e) {
            Log.w(TAG, e);
            database.markAsLegacyVersion(messageId);
        } catch (InvalidMessageException e) {
            Log.w(TAG, e);
            database.markAsDecryptFailed(messageId);
        } catch (DuplicateMessageException e) {
            Log.w(TAG, e);
            database.markAsDecryptDuplicate(messageId);
        } catch (NoSessionException | UntrustedIdentityException e) {
            Log.w(TAG, e);
            database.markAsNoSession(messageId);
        }
        return response;
    }

    private static void handleSecureMessage(Context context, MasterSecret masterSecret, long messageId, long threadId,
                                            IncomingTextMessage message)
            throws NoSessionException, DuplicateMessageException,
            InvalidMessageException, LegacyMessageException,
            UntrustedIdentityException {
        EncryptingSmsDatabase database = DatabaseFactory.getEncryptingSmsDatabase(context);
        SmsCipher cipher = new SmsCipher(new SilenceSignalProtocolStore(context, masterSecret, message.getSubscriptionId()));
        IncomingTextMessage plaintext = cipher.decrypt(context, message);

        database.updateMessageBody(masterSecret, messageId, plaintext.getMessageBody());

        if (message.isEndSession()) SecurityEvent.broadcastSecurityUpdateEvent(context, threadId);
    }

    private static void handlePreKeySignalMessage(Context context, MasterSecret masterSecret, long messageId, long threadId,
                                                  IncomingPreKeyBundleMessage message)
            throws NoSessionException, DuplicateMessageException,
            InvalidMessageException, LegacyMessageException {
        EncryptingSmsDatabase database = DatabaseFactory.getEncryptingSmsDatabase(context);

        try {
            SmsCipher smsCipher = new SmsCipher(new SilenceSignalProtocolStore(context, masterSecret, message.getSubscriptionId()));
            IncomingEncryptedMessage plaintext = smsCipher.decrypt(context, message);

            database.updateBundleMessageBody(masterSecret, messageId, plaintext.getMessageBody());

            SecurityEvent.broadcastSecurityUpdateEvent(context, threadId);
        } catch (InvalidVersionException e) {
            Log.w(TAG, e);
            database.markAsInvalidVersionKeyExchange(messageId);
        } catch (UntrustedIdentityException e) {
            Log.w(TAG, e);
        }
    }

    private static OutgoingKeyExchangeMessage handleKeyExchangeMessage(Context context, MasterSecret masterSecret, long messageId, long threadId,
                                                                       IncomingKeyExchangeMessage message, boolean manualOverride, boolean isSms) {
        EncryptingSmsDatabase database = DatabaseFactory.getEncryptingSmsDatabase(context);

        try {
            SmsCipher cipher = new SmsCipher(new SilenceSignalProtocolStore(context, masterSecret, message.getSubscriptionId()));
            OutgoingKeyExchangeMessage response = cipher.process(context, message);

            if (shouldSend(context, manualOverride)) {
                database.markAsProcessedKeyExchange(messageId);
                SecurityEvent.broadcastSecurityUpdateEvent(context, threadId);
            }
            if (isSms && response != null) {
                MessageSender.send(context, masterSecret, response, threadId, true);
            }
            return response;
        } catch (InvalidVersionException e) {
            Log.w(TAG, e);
            database.markAsInvalidVersionKeyExchange(messageId);
        } catch (InvalidMessageException e) {
            Log.w(TAG, e);
            database.markAsCorruptKeyExchange(messageId);
        } catch (LegacyMessageException e) {
            Log.w(TAG, e);
            database.markAsLegacyVersion(messageId);
            if (shouldSend(context, manualOverride)) {
                Log.w(TAG, "Legacy message found, sending updated key exchange message...");
                Recipients recipients = RecipientFactory.getRecipientsFromString(context, message.getSender(), false);
                KeyExchangeInitiator.initiate(context, masterSecret, recipients, false, message.getSubscriptionId());
                database.markAsProcessedKeyExchange(messageId);
            }
        } catch (StaleKeyExchangeException e) {
            Log.w(TAG, e);
            database.markAsStaleKeyExchange(messageId);
        } catch (UntrustedIdentityException e) {
            Log.w(TAG, e);

            Recipients recipients = RecipientFactory.getRecipientsFromString(context, message.getSender(), false);
            long recipientId = recipients.getPrimaryRecipient().getRecipientId();

            database.notifyConversationListeners(threadId);
            database.setMismatchedIdentity(messageId, recipientId, e.getUntrustedIdentity());
        }
        return null;
    }

    private static boolean shouldSend(Context context, boolean manualOverride) {
        return (SilencePreferences.isAutoRespondKeyExchangeEnabled(context) || manualOverride);
    }

    private static void handleXmppExchangeMessage(Context context, MasterSecret masterSecret, long messageId, long threadId,
                                                  IncomingXmppExchangeMessage message)
            throws NoSessionException, DuplicateMessageException, InvalidMessageException, LegacyMessageException {
        EncryptingSmsDatabase database = DatabaseFactory.getEncryptingSmsDatabase(context);
        database.markAsXmppExchange(messageId);
    }

    private static String getAsymmetricDecryptedBody(Context context, MasterSecret masterSecret, String body, int subscriptionId)
            throws InvalidMessageException {
        try {
            AsymmetricMasterSecret asymmetricMasterSecret = MasterSecretUtil.getAsymmetricMasterSecret(context, masterSecret);
            AsymmetricMasterCipher asymmetricMasterCipher = new AsymmetricMasterCipher(asymmetricMasterSecret);

            return asymmetricMasterCipher.decryptBody(body);
        } catch (IOException e) {
            throw new InvalidMessageException(e);
        }
    }

    private static IncomingTextMessage createIncomingTextMessage(Context context, MasterSecret masterSecret, SmsMessageRecord record)
            throws InvalidMessageException {
        String plaintextBody = record.getBody().getBody();

        if (record.isAsymmetricEncryption()) {
            plaintextBody = getAsymmetricDecryptedBody(context, masterSecret, record.getBody().getBody(), record.getSubscriptionId());
        }

        IncomingTextMessage message = new IncomingTextMessage(record.getRecipients().getPrimaryRecipient().getNumber(),
                record.getRecipientDeviceId(),
                record.getDateSent(),
                plaintextBody,
                record.getSubscriptionId());

        if (record.isEndSession()) {
            return new IncomingEndSessionMessage(message);
        } else if (record.isBundleKeyExchange()) {
            return new IncomingPreKeyBundleMessage(message, message.getMessageBody());
        } else if (record.isKeyExchange()) {
            return new IncomingKeyExchangeMessage(message, message.getMessageBody());
        } else if (record.isXmppExchange()) {
            return new IncomingXmppExchangeMessage(message, message.getMessageBody());
        } else if (record.isSecure()) {
            return new IncomingEncryptedMessage(message, message.getMessageBody());
        }

        return message;
    }
}
