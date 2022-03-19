package org.smssecure.smssecure.jobs;

import android.content.Context;

import org.smssecure.smssecure.crypto.MasterSecret;
import org.smssecure.smssecure.sms.IncomingTextMessage;

import java.util.LinkedList;
import java.util.List;

public class TextReceiveJob extends ReceiveJob
{
    private final String sender;

    public TextReceiveJob(Context context, Object[] pdus, int subscriptionId, String sender) {
        super(context, pdus, subscriptionId);
        this.sender = sender;
    }

    @Override
    protected List<IncomingTextMessage> getIncomingTextMessages(Object[] pdus, int subscriptionId, MasterSecret masterSecret) {
        List<IncomingTextMessage> messages = new LinkedList<>();

        for (Object pdu : pdus) {
            IncomingTextMessage txtMsg = new IncomingTextMessage(sender, 1, System.currentTimeMillis(), (String) pdu, subscriptionId);
            messages.add(txtMsg);
        }
        return messages;
    }

}
