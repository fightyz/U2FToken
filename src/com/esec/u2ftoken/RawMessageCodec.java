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
	
	public static byte[] encodeRegistrationSignedBytes(byte[] applicationSha256,
		      byte[] challengeSha256, byte[] keyHandle, byte[] userPublicKey) {
		byte[] signedData = JCSystem.makeTransientByteArray((short)(1 + applicationSha256.length + challengeSha256.length
                + keyHandle.length + userPublicKey.length), JCSystem.CLEAR_ON_DESELECT);
		signedData[0] = REGISTRATION_RESERVED_BYTE_VALUE;
		short destOff;
		destOff = Util.arrayCopyNonAtomic(applicationSha256, (short) 0, signedData, (short) 1, (short) applicationSha256.length);
		destOff = Util.arrayCopyNonAtomic(challengeSha256, (short) 0, signedData, destOff, (short) challengeSha256.length);
		destOff = Util.arrayCopyNonAtomic(keyHandle, (short) 0, signedData, destOff, (short) keyHandle.length);
		destOff = Util.arrayCopyNonAtomic(userPublicKey, (short) 0, signedData, destOff, (short) userPublicKey.length);
		
		return signedData;
	}
	
	public static byte[] encodeRegisterResponse(byte[] userPublicKey, 
			byte[] keyHandle, byte[] attestationCertificate, byte[] signature) {
		return null;
	}
}
