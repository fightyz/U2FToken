package com.esec.u2ftoken;

import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;

/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-22 下午09:49:02 
 * 
 */
public interface KeyPairGenerator {
	KeyPair newKeyPair();
//	byte[] encodePublicKey(PublicKey publicKey);
	short encodePrivateKey(PrivateKey privateKey, byte[] encPrivatekey);
}
