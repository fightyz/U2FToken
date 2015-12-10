package com.esec.u2ftoken;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-10 下午06:51:23 
 * 与密钥相关的操作和数据封装类
 */
public class SecretKey {
	
	public static final byte MODE_ENCRYPT = 0x01; // 加密模式
	public static final byte MODE_DECRYPT = 0x02; // 解密模式
	
	/**
	 * key wrap的实体，这里采用AES算法
	 */
	private AESKey mKeyInstance;
	
	/**
	 * 初始化key wrap算法的密钥，保存在mKeyInstance中
	 * 采用AES-256，生成的AES密钥有256位
	 */
	public SecretKey() {
		mKeyInstance = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		byte[] keyData = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayFillNonAtomic(keyData, (short) 0, (short) keyData.length, (byte) 0x00);
		mKeyInstance.setKey(keyData, (short) 0);
	}
	
	/**
	 * key wrap算法，这里采用 AES-256 的 ALG_AES_BLOCK_128_CBC_NOPAD
	 * @param data 需要 wrap 的数据
	 * @param inOffset
	 * @param inLength
	 * @param outBuff
	 * @param outOffset
	 * @param mode 加密或解密。 Cipher.MODE_ENCRYPT 或 Cipher.MODE_DECRYPT
	 */
	public void KeyWrap(byte[] data, short inOffset, short inLength, byte[] outBuff, short outOffset, byte mode) {
		Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cipher.init(mKeyInstance, mode); // 初始向量(iv)是0
		
		// 加密或解密，doFinal后，cipher对象将被重置
		try {
			cipher.doFinal(data, inOffset, inLength, outBuff, outOffset);
		} catch(Exception e) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
	}
}
