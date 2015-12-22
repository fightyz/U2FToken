package com.esec.u2ftoken;

import javacard.security.KeyPair;

/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-22 下午10:07:03 
 * 
 */
public interface KeyHandleGenerator {
//	byte[] generateKeyHandle(byte[] applicationSha256, KeyPair keyPair);
	byte[] generateKeyHandle(byte[] applicationSha256, byte[] privateKey);
}
