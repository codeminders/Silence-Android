/**
 * Copyright (C) 2011 Whisper Systems
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
package org.smssecure.smssecure.util;

import android.util.Log;

import org.smssecure.smssecure.sms.SmsTransportDetails;

import java.io.UnsupportedEncodingException;

import kotlin.text.Charsets;

public class EncryptedSmsCharacterCalculator extends CharacterCalculator {

  public static final String TAG = EncryptedSmsCharacterCalculator.class.getSimpleName();

  private CharacterState calculateSingleRecordCharacters(int charactersSpent) {
    int charactersRemaining = SmsTransportDetails.ENCRYPTED_SINGLE_MESSAGE_BODY_MAX_SIZE - charactersSpent;

    return new CharacterState(1, charactersRemaining, SmsTransportDetails.ENCRYPTED_SINGLE_MESSAGE_BODY_MAX_SIZE);
  }

  private CharacterState calculateMultiRecordCharacters(int charactersSpent) {
    int charactersInFirstRecord = SmsTransportDetails.ENCRYPTED_SINGLE_MESSAGE_BODY_MAX_SIZE;
    int spillover               = charactersSpent - charactersInFirstRecord;
    int spilloverMessagesSpent  = spillover / SmsTransportDetails.MULTI_MESSAGE_MAX_BYTES;

    if ((spillover % SmsTransportDetails.MULTI_MESSAGE_MAX_BYTES) > 0)
      spilloverMessagesSpent++;

    int charactersRemaining = (SmsTransportDetails.MULTI_MESSAGE_MAX_BYTES * spilloverMessagesSpent) - spillover;

    return new CharacterState(spilloverMessagesSpent+1, charactersRemaining, SmsTransportDetails.MULTI_MESSAGE_MAX_BYTES);
  }

  @Override
  public CharacterState calculateCharacters(String messageBody) {
    int messageBytesLength;
    try {
      messageBytesLength = messageBody.getBytes("ISO-8859-5").length;
    } catch (UnsupportedEncodingException e) {
      Log.e(TAG, e.getMessage(), e);
      messageBytesLength = messageBody.getBytes(Charsets.UTF_8).length;
    }
    if (messageBytesLength <= SmsTransportDetails.ENCRYPTED_SINGLE_MESSAGE_BODY_MAX_SIZE) {
      return calculateSingleRecordCharacters(messageBytesLength);
    } else {
      return calculateMultiRecordCharacters(messageBytesLength);
    }
  }
}
