/**
 * Copyright (C) 2011 Whisper Systems
 * Copyright (C) 2013 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.smssecure.smssecure.crypto;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.util.Log;
import android.widget.Toast;

import org.smssecure.smssecure.R;
import org.smssecure.smssecure.crypto.storage.SilenceIdentityKeyStore;
import org.smssecure.smssecure.crypto.storage.SilencePreKeyStore;
import org.smssecure.smssecure.crypto.storage.SilenceSessionStore;
import org.smssecure.smssecure.database.NoSuchMessageException;
import org.smssecure.smssecure.protocol.KeyExchangeMessage;
import org.smssecure.smssecure.recipients.Recipient;
import org.smssecure.smssecure.recipients.Recipients;
import org.smssecure.smssecure.sms.MessageSender;
import org.smssecure.smssecure.sms.OutgoingEndSessionMessage;
import org.smssecure.smssecure.sms.OutgoingKeyExchangeMessage;
import org.smssecure.smssecure.sms.OutgoingTextMessage;
import org.smssecure.smssecure.transport.UndeliverableMessageException;
import org.smssecure.smssecure.util.Base64;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.util.List;

public class KeyExchangeInitiator {

  private static final String TAG = KeyExchangeInitiator.class.getSimpleName();

  public static void abort(final Context context, final MasterSecret masterSecret, final Recipients recipients, final int subscriptionId) {
    try {
      abort(context, masterSecret, recipients, subscriptionId, true);
    } catch (NoSuchMessageException | UntrustedIdentityException | UndeliverableMessageException e) {
      Log.e(TAG, e.getMessage(), e);
    }
  }
  public static EncryptedMultipartMessage abort(final Context context, final MasterSecret masterSecret, final Recipients recipients, final int subscriptionId, final boolean sendSms) throws NoSuchMessageException, UntrustedIdentityException, UndeliverableMessageException {
    OutgoingEndSessionMessage endSessionMessage = new OutgoingEndSessionMessage(new OutgoingTextMessage(recipients, "TERMINATE", subscriptionId));
    if (sendSms) {
      MessageSender.send(context, masterSecret, endSessionMessage, -1, false);
      return null;
    } else {
      return MessageSender.encrypt(context, masterSecret, endSessionMessage, -1);
    }
  }

  public static void initiate(final Context context, final MasterSecret masterSecret, final Recipients recipients, boolean promptOnExisting, final int subscriptionId) {
    if (promptOnExisting && hasInitiatedSession(context, masterSecret, recipients, subscriptionId)) {
      AlertDialog.Builder dialog = new AlertDialog.Builder(context);
      dialog.setTitle(R.string.KeyExchangeInitiator_initiate_despite_existing_request_question);
      dialog.setMessage(R.string.KeyExchangeInitiator_youve_already_sent_a_session_initiation_request_to_this_recipient_are_you_sure);
      dialog.setIconAttribute(R.attr.dialog_alert_icon);
      dialog.setCancelable(true);
      dialog.setPositiveButton(R.string.KeyExchangeInitiator_send, new DialogInterface.OnClickListener() {
        public void onClick(DialogInterface dialog, int which) {
          initiateKeyExchange(context, masterSecret, recipients, subscriptionId);
        }
      });
      dialog.setNegativeButton(android.R.string.cancel, null);
      dialog.show();
    } else {
      initiateKeyExchange(context, masterSecret, recipients, subscriptionId);
    }
  }

  public static void initiateKeyExchange(Context context, MasterSecret masterSecret, Recipients recipients, int subscriptionId) {
    KeyExchangeInitResult keyExchangeInitResult = initiateKeyExchange(context, masterSecret, recipients, subscriptionId, true);
    if (keyExchangeInitResult.getErrorResId() != null) {
      Toast.makeText(context, keyExchangeInitResult.getErrorResId(), Toast.LENGTH_LONG).show();
    }
  }

  public static KeyExchangeInitResult initiateKeyExchange(Context context, MasterSecret masterSecret, Recipients recipients, int subscriptionId, boolean sendSms) {
    Recipient         recipient         = recipients.getPrimaryRecipient();
    SessionStore      sessionStore      = new SilenceSessionStore(context, masterSecret, subscriptionId);
    PreKeyStore       preKeyStore       = new SilencePreKeyStore(context, masterSecret, subscriptionId);
    SignedPreKeyStore signedPreKeyStore = new SilencePreKeyStore(context, masterSecret, subscriptionId);
    IdentityKeyStore  identityKeyStore  = new SilenceIdentityKeyStore(context, masterSecret, subscriptionId);

    SessionBuilder    sessionBuilder    = new SessionBuilder(sessionStore, preKeyStore, signedPreKeyStore,
                                                             identityKeyStore, new SignalProtocolAddress(recipient.getNumber(), 1));

    List<String> multipartEncryptedText = null;
    Integer errorResId = null;
    if (identityKeyStore.getIdentityKeyPair() != null) {
      KeyExchangeMessage         keyExchangeMessage = sessionBuilder.process();
      String                     serializedMessage  = Base64.encodeBytesWithoutPadding(keyExchangeMessage.serialize());
      OutgoingKeyExchangeMessage textMessage        = new OutgoingKeyExchangeMessage(recipients, serializedMessage, subscriptionId);


      if (sendSms) {
        MessageSender.send(context, masterSecret, textMessage, -1, false);
      } else {
        try {
          multipartEncryptedText = MessageSender.encrypt(context, masterSecret, textMessage, -1).getMultipartEncryptedText();
        } catch (NoSuchMessageException | UntrustedIdentityException | UndeliverableMessageException e) {
          Log.e(TAG, e.getMessage(), e);
        }
      }
    } else {
      errorResId = R.string.VerifyIdentityActivity_you_do_not_have_an_identity_key;
    }
    return new KeyExchangeInitResult(multipartEncryptedText, errorResId);
  }

  public static boolean hasInitiatedSession(Context context, MasterSecret masterSecret,
                                             Recipients recipients, int subscriptionId)
  {
    Recipient     recipient     = recipients.getPrimaryRecipient();
    SessionStore  sessionStore  = new SilenceSessionStore(context, masterSecret, subscriptionId);
    SessionRecord sessionRecord = sessionStore.loadSession(new SignalProtocolAddress(recipient.getNumber(), 1));

    return sessionRecord.getSessionState().hasPendingKeyExchange();
  }
}
