package com.esec.u2ftoken;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-23 下午04:15:44 
 * Raw Message Formats
 */
public class RawMessageCodec {
	public static final byte REGISTRATION_RESERVED_BYTE_VALUE = (byte) 0x05;
	public static final byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = (byte) 0x00;
	
	public static final byte APDU_TYPE_NOT_EXTENDED = (byte) 0x00;
	public static final byte APDU_TYPE_EXTENDED = (byte) 0x01;
	
	public static byte[] encodeRegistrationSignedBytes(byte[] applicationSha256,
		      byte[] challengeSha256, byte[] keyHandle, byte[] userPublicKey) {
		byte[] signedData = JCSystem.makeTransientByteArray((short)(1 + applicationSha256.length + challengeSha256.length
                + keyHandle.length + userPublicKey.length), JCSystem.CLEAR_ON_DESELECT);
		signedData[0] = REGISTRATION_SIGNED_RESERVED_BYTE_VALUE;
		short destOff;
		destOff = Util.arrayCopyNonAtomic(applicationSha256, (short) 0, signedData, (short) 1, (short) applicationSha256.length);
		destOff = Util.arrayCopyNonAtomic(challengeSha256, (short) 0, signedData, destOff, (short) challengeSha256.length);
		destOff = Util.arrayCopyNonAtomic(keyHandle, (short) 0, signedData, destOff, (short) keyHandle.length);
		destOff = Util.arrayCopyNonAtomic(userPublicKey, (short) 0, signedData, destOff, (short) userPublicKey.length);
		
		return signedData;
	}
	
	/**
	 * Register response. [0] is apdu type and [1,2] is sent message's offset.  
	 * @param userPublicKey
	 * @param keyHandle
	 * @param attestationCertificate
	 * @param signature
	 * @return
	 */
	public static byte[] encodeRegisterResponse(byte[] userPublicKey, 
			byte[] keyHandle, byte[] attestationCertificate, byte[] signature) {
		byte[] registerResponse = JCSystem.makeTransientByteArray((short)(3 + 1 + 65 + 1 + keyHandle.length
				+ attestationCertificate.length + signature.length), JCSystem.CLEAR_ON_DESELECT);
		registerResponse[0] = APDU_TYPE_NOT_EXTENDED;
		registerResponse[3] = REGISTRATION_RESERVED_BYTE_VALUE;
		short destOff;
		destOff = Util.arrayCopyNonAtomic(userPublicKey, (short) 0, registerResponse, (short) 4, (short) userPublicKey.length);
		registerResponse[destOff] = (byte) keyHandle.length;
		destOff++;
		destOff = Util.arrayCopyNonAtomic(keyHandle, (short) 0, registerResponse, destOff, (short) keyHandle.length);
		destOff = Util.arrayCopyNonAtomic(attestationCertificate, (short) 0, registerResponse, destOff, (short) attestationCertificate.length);
		destOff = Util.arrayCopyNonAtomic(signature, (short) 0, registerResponse, destOff, (short) signature.length);
		Util.setShort(registerResponse, (short) 1, (short) 3);
		return registerResponse;
	}
}
