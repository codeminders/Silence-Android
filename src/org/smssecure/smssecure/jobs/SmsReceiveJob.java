package org.smssecure.smssecure.jobs;

import android.content.Context;
import android.telephony.SmsMessage;

import org.smssecure.smssecure.crypto.MasterSecret;
import org.smssecure.smssecure.sms.IncomingTextMessage;

import java.util.LinkedList;
import java.util.List;

public class SmsReceiveJob extends ReceiveJob {

  private static final long serialVersionUID = 1L;

  public SmsReceiveJob(Context context, Object[] pdus, int subscriptionId) {
    super(context, pdus, subscriptionId);
  }

  @Override
  protected List<IncomingTextMessage> getIncomingTextMessages(Object[] pdus, int subscriptionId, MasterSecret masterSecret) {
    List<IncomingTextMessage> messages = new LinkedList<>();

    for (Object pdu : pdus) {
      SmsMessage msg = SmsMessage.createFromPdu((byte[]) pdu);
      if (msg != null){
        messages.add(new IncomingTextMessage(msg, subscriptionId, masterSecret == null));
      }
    }
    return messages;
  }
}
