package com.esec.u2ftoken;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacardx.crypto.Cipher;

/** 
 * Generate Key Handle with AES-128
 * @author Yang Zhou 
 * @version 创建时间：2015-12-22 下午10:11:13 
 */
public class AesKeyHandle implements KeyHandleGenerator {

	/**
	 * Wrap the hash of appid and private key to generate Key Handle
	 * @param applicationSha256 Hash of appid.
	 * @param privateKey Private key to authenticate.
	 * @return
	 */
	public byte[] generateKeyHandle(byte[] applicationSha256, ECPrivateKey privateKey) {
		// TODO Auto-generated method stub
//		byte[] privKey = privateKey.getS(buffer, offset)
//		short keyHandleLen = (short)(applicationSha256.length + privateKey.length);
//		byte[] keyHandle = JCSystem.makeTransientByteArray(keyHandleLen, JCSystem.CLEAR_ON_DESELECT);
//		
//		AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
//		byte[] keyData = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
//		Util.arrayFillNonAtomic(keyData, (short) 0, (short) keyData.length, (byte) 0x00);
//		aesKey.setKey(keyData, (short) 0);
//		
//		Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
//		cipher.init(aesKey, Cipher.MODE_ENCRYPT);
////		short sendLen = cipher.doFinal(data, (short) 0, (short) data.length, buffer, (short) 0);
		
		return null;
	}

}
