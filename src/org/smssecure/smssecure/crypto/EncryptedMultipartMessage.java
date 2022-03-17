package org.smssecure.smssecure.crypto;

import java.util.List;

public class EncryptedMultipartMessage {
    private final long allocatedThreadId;
    private final long messageId;
    private final int type;
    private final List<String> multipartEncryptedText;
    private final String plainText;

    public EncryptedMultipartMessage(long allocatedThreadId, long messageId,
                                     int type, List<String> multipartEncryptedText, String plainText)
    {
        this.allocatedThreadId = allocatedThreadId;
        this.messageId = messageId;
        this.type = type;
        this.multipartEncryptedText = multipartEncryptedText;
        this.plainText = plainText;
    }

    public long getAllocatedThreadId()
    {
        return allocatedThreadId;
    }

    public long getMessageId()
    {
        return messageId;
    }

    public int getType()
    {
        return type;
    }

    public List<String> getMultipartEncryptedText()
    {
        return multipartEncryptedText;
    }

    public String getPlainText()
    {
        return plainText;
    }
}
