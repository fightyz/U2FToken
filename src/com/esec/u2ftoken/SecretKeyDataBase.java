package com.esec.u2ftoken;

import javacard.security.ECPrivateKey;
import javacard.security.PrivateKey;

/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-23 下午07:55:49 
 * Store user's ECC private key
 */
public class SecretKeyDataBase {
	
	private static SecretKeyDataBase INSTANCE = null;
	private PrivateKey[] mPrivateKeys;
	private short counter;
	
	public static SecretKeyDataBase getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new SecretKeyDataBase();
		}
		return INSTANCE;
	}
	
	private SecretKeyDataBase() {
		counter = 0;
		mPrivateKeys = new PrivateKey[30]; 
	}
	
	// TODO resize array mPrivateKeys, if counter exceeds the length, considering the JC's system storage left.
	public short storeSecretKey(PrivateKey privateKey) {
		mPrivateKeys[counter] = privateKey;
		counter++;
		return (short)(counter - 1);
	}
}
