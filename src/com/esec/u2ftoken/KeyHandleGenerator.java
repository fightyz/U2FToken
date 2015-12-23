package com.esec.u2ftoken;

import javacard.security.ECPrivateKey;

/** 
 * Generate a key handle.
 * @author Yang Zhou 
 */
public interface KeyHandleGenerator {
	
	public byte[] generateKeyHandle(byte[] applicationSha256, ECPrivateKey privateKey);
}
