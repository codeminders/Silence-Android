package org.smssecure.smssecure.crypto;

import java.util.List;

public class KeyExchangeInitResult {
    private final List<String> message;
    private final Integer errorResId;


    public KeyExchangeInitResult(List<String> message, Integer errorResId) {
        this.message = message;
        this.errorResId = errorResId;
    }

    public List<String> getMessage() {
        return message;
    }

    public Integer getErrorResId() {
        return errorResId;
    }
}
