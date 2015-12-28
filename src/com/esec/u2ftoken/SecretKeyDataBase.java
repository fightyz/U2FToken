package com.esec.u2ftoken;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.PrivateKey;

/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-23 下午07:55:49 
 * Store user's ECC private key
 */
public class SecretKeyDataBase {
	
	private static final short U2F_SW_INVALID_KEY_HANDLE = ISO7816.SW_WRONG_DATA;
	private static SecretKeyDataBase INSTANCE = null;
	private ECPrivateKey[] mPrivateKeys;
	private short counter;
	
	public static SecretKeyDataBase getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new SecretKeyDataBase();
		}
		return INSTANCE;
	}
	
	private SecretKeyDataBase() {
		counter = 0;
		mPrivateKeys = new ECPrivateKey[30]; 
	}
	
	// TODO resize array mPrivateKeys, if counter exceeds the length, considering the JC's system storage left.
	public short storeSecretKey(ECPrivateKey privateKey) {
		mPrivateKeys[counter] = privateKey;
		counter++;
		return (short)(counter - 1);
	}
	
	public ECPrivateKey getKey(short index) {
		if (index >= counter) {
			ISOException.throwIt(U2F_SW_INVALID_KEY_HANDLE);
		}
		return mPrivateKeys[index];
	}
}
