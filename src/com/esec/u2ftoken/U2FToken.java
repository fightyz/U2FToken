package com.esec.u2ftoken;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.CardException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class U2FToken extends Applet {
	/**
	 * 64 bytes, contains 32 bytes application sha256 and 32 bytes challenge sha256(this is a hash of Client Data)
	 */
	private static final short LEN_REGISTRATION_REQUEST_MESSAGE = 64;
	
	/**
	 * 32 bytes, this is the hash of appid
	 */
	private static final short LEN_APPLICATIONSHA256 = 32;
	
	/**
	 * 32 bytes, this is the hash of Client Data
	 */
	private static final short LEN_CHALLENGESHA256 = 32;
	
	public static final byte CLA_7816 = 0x00;
	private static final byte CLA_U2F = 0x00;
	
	public static final byte INS_TEST_ENCRYPT = 0x10;
	public static final byte INS_TEST_DECRYPT = 0x20;
	public static final byte INS_TEST_SEEECPUBKEY = 0x30;
	public static final byte INS_TEST_VERIFY = 0x40;
	public static final byte INS_TEST_BOUNCY_CASTLE = 0x50;
	public static final byte INS_TEST_GENERIC = 0x60;
	
	public static final byte INS_U2F_REGISTER = 0x01; // Registration command
	public static final byte INS_U2F_AUTHENTICATE = 0x02; // Authenticate/sign command
	public static final byte INS_U2F_VERSION = 0x03; //Read version string command
	public static final byte INS_U2F_CHECK_REGISTER = 0x04; // Registration command that incorporates checking key handles
	public static final byte INS_U2F_AUTHENTICATE_BATCH = 0x05; // Authenticate/sign command for a batch of key handles
	
	/**
	 * 存储attestation证书的二进制文件。FID是EF01
	 */
	public BinaryEF attestationCertFile;
	
	/**
	 * 版本号："U2F_V2"
	 */
	private static final byte[] version = {(byte)0x55, (byte)0x32, (byte)0x46, (byte)0x5F, (byte)0x56, (byte)0x32};
	
	private static VariableLengthRecordEF mAttestationCertificate;
	
	public SecretKeys mSecretKey;
	private AESKey mAESKeyInstance;
	
	private KeyPair pair;
	private ECPublicKey pubKey;
	private ECPrivateKey privKey;
	private boolean GENED = false;
	private Signature signature;
	
	private KeyHandleGenerator mKeyHandleGenerator;
	
	public U2FToken() {
		mKeyHandleGenerator = new IndexKeyHandle();
	}
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new U2FToken().register();
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			getSelectResponse(apdu);
			return;
		}

		// Get APDU header
		byte[] buf = apdu.getBuffer();
		byte cla = buf[ISO7816.OFFSET_CLA];
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short lc = (short)(buf[ISO7816.OFFSET_LC] & 0x00FF);
		
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) INS_TEST_ENCRYPT:
//			try {
//				KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
//			} catch(CryptoException e) {
//				short reason = e.getReason();
////				ISOException.throwIt(JCSystem.getVersion());
////				ISOException.throwIt(reason);
//			}
			try {
				Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			} catch(CryptoException e) {
				ISOException.throwIt(JCSystem.getVersion());
				short reason = e.getReason();
				ISOException.throwIt(reason);
			}
			AESencrypt(apdu, cla, p1, p2, lc);
			break;
		case (byte) INS_TEST_DECRYPT:
//			decrypt(apdu, cla, p1, p2, lc);
			break;
		case (byte) INS_U2F_REGISTER: // U2F register command
			u2fRegister(apdu, cla, p1, p2, lc);
			break;
			
		case (byte) INS_TEST_SEEECPUBKEY:
			seeECPubKey(apdu, cla, p1, p2, lc);
			break;
		
		case (byte) INS_TEST_VERIFY:
			verifyKey(apdu, cla, p1, p2, lc);
			break;
			
		case (byte) INS_TEST_GENERIC:
			byte[] test = genericTest(apdu, cla, p1, p2, lc);
			Util.arrayCopyNonAtomic(test, (short) 0, buf, (short) 0, (short) test.length);
			apdu.setOutgoingAndSend((short) 0, (short) test.length);
			break;
			
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	/**
	 * 选择applet时，返回"U2F_V2"
	 * @param apdu
	 */
	private void getSelectResponse(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopyNonAtomic(version, (short)0, buffer, (short)0, (short)version.length);
		apdu.setOutgoingAndSend((short)0, (short)version.length);
	}

	/**
	 * Pull registration request message. Generate registration response message. 
	 * @param apdu
	 * @param cla 0x00
	 * @param p1 待定，u2f协议例子中是0x03，不知道为什么。不知道会不会是test-of-user-presence
	 * @param p2
	 * @param lc
	 */
	private void u2fRegister(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		if (cla != CLA_U2F) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		short readCount = apdu.setIncomingAndReceive();		
		if (readCount != LEN_REGISTRATION_REQUEST_MESSAGE) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		byte[] buffer = apdu.getBuffer();
		SharedMemory sharedMemory = SharedMemory.getInstance();
		
		byte[] applicationSha256 = sharedMemory.m32BytesApplicationSha256;
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, applicationSha256, (short) 0, LEN_APPLICATIONSHA256);
		
		byte[] challengeSha256 = sharedMemory.m32BytesChallengeSha256;
		Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA + LEN_APPLICATIONSHA256),
				challengeSha256, (short) 0, LEN_CHALLENGESHA256);
		
		// Generate user authentication key
		KeyPair userKeyPair = SecP256r1.newKeyPair();
		userKeyPair.genKeyPair();
		ECPrivateKey privKey = (ECPrivateKey)userKeyPair.getPrivate();
		ECPublicKey pubKey = (ECPublicKey)userKeyPair.getPublic();
		
		// Store user's private key locally. Generate Key Handle.
		byte[] keyHandle = mKeyHandleGenerator.generateKeyHandle(applicationSha256, privKey);
		{
			// TODO May be store tuple(KeyHandle, KeyPair) in two Linear EF. They can be mapped by the index.
		}
		
		short userPublicKeyLen = pubKey.getW(buffer, (short) 0);
		byte[] userPublicKey = sharedMemory.m65BytesUserPublicKey;
		Util.arrayCopyNonAtomic(buffer, (short) 0, userPublicKey, (short) 0, userPublicKeyLen);
		
		// Sign data
		byte[] signedData = RawMessageCodec.encodeRegistrationSignedBytes(
				applicationSha256,
				challengeSha256,
				keyHandle,
				userPublicKey
				);
		
		// Generate signature use attestation private key
		Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
		signature.init(privKey, Signature.MODE_SIGN);
		short signLen = signature.sign(signedData, (short) 0, (short) signedData.length, buffer, (short) 0);
		
		//生成认证公私钥
//		KeyPair pair = SecP256r1.newKeyPair();
//		pair.genKeyPair();
//		ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
//		ECPrivateKey privKey = (ECPrivateKey) pair.getPrivate();
//		// 生成KeyHandle
//		//TODO 生成KeyHandle，里面的AppID似乎只能是Client传过来的AppID的hash？
//		
////		short sendlen = pubKey.getW(buffer, (short) 0);
//		short sendlen = privKey.getS(buffer, (short) 0);
//		
//		if (GENED == false) {
//			pair = SecP256r1.newKeyPair();
//			pair.genKeyPair();
//			GENED = true;
//		}
//		ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
//		ECPrivateKey privKey = (ECPrivateKey) pair.getPrivate();
//		// 生成KeyHandle
//		//TODO 生成KeyHandle，里面的AppID似乎只能是Client传过来的AppID的hash？
//		
////		short sendlen = pubKey.getW(buffer, (short) 0);
//		short sendlen = privKey.getS(buffer, (short) 0);
////		privKey.get
////		pubKey.
//		
//		apdu.setOutgoingAndSend((short) 0, sendlen);
	}
	
	private void seeECPubKey(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		byte[] buffer = apdu.getBuffer();
		if (cla != CLA_7816) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		//生成认证公私钥
//		KeyPair pair = SecP256r1.newKeyPair();
//		pair.genKeyPair();
//		ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
//		ECPrivateKey privKey = (ECPrivateKey) pair.getPrivate();
//		// 生成KeyHandle
//		//TODO 生成KeyHandle，里面的AppID似乎只能是Client传过来的AppID的hash？
//		
////		short sendlen = pubKey.getW(buffer, (short) 0);
//		short sendlen = privKey.getS(buffer, (short) 0);
		
//		if (GENED == false) {
//			pair = SecP256r1.newKeyPair();
//			pair.genKeyPair();
//			GENED = true;
//		}
//		ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
//		ECPrivateKey privKey = (ECPrivateKey) pair.getPrivate();
//		// 生成KeyHandle
//		//TODO 生成KeyHandle，里面的AppID似乎只能是Client传过来的AppID的hash？
//		
////		short sendlen = pubKey.getW(buffer, (short) 0);
//		short sendlen = pubKey.getW(buffer, (short) 0);
//		privKey.get
//		pubKey.
		
//		apdu.setOutgoingAndSend((short) 0, sendlen);
	}
	
	public void verifyKey(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		byte[] buffer = apdu.getBuffer();
		if (cla != CLA_7816) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		if (GENED == false) {
//			pair = SecP256r1.newKeyPair();
//			try {
//				pair.genKeyPair();
//			} catch(CryptoException e) {
//				ISOException.throwIt(JCSystem.getVersion());
//			}
			
			GENED = true;
		}
		ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
		ECPrivateKey privKey = (ECPrivateKey) pair.getPrivate();
//		byte[] pubData = {0x04, 0x00, (byte)0xb9, (byte)0x8f, (byte)0xcf, (byte)0xc3, (byte)0xc0, (byte)0xae, (byte)0x95, 0x6a, 0x5b, 0x12, 0x6d, (byte)0xbe, 0x43, (byte)0xe4, 0x7f, 0x09, 0x0d, (byte)0xde, 0x02, (byte)0xd2, 0x6b, 0x28, (byte)0x86, (byte)0xed, 0x2b, (byte)0xd7, (byte)0xe2, (byte)0xc2, 0x69, (byte)0xc1, (byte)0x89, (byte)0xb2, 0x53, (byte)0x96, (byte)0xc1, 0x2d, (byte)0xbf, 0x4c, 0x30, (byte)0xae, (byte)0xd5, (byte)0xd5, 0x3c, (byte)0xb5, (byte)0xf9, 0x3b, 0x20, 0x37, (byte)0x83, (byte)0x88, (byte)0x9f, 0x34, 0x74, (byte)0xf5, 0x6c, (byte)0x97, 0x1e, 0x0a, (byte)0xa9, (byte)0xe7, (byte)0xfa, (byte)0xa6, 0x69};
//		pubKey.setW(pubData, (short) 0, (short)pubData.length);
//		byte[] privData = {(byte)0x25, (byte)0xc9, (byte)0xec, (byte)0xdc, (byte)0x4c, (byte)0x59, (byte)0xa3, (byte)0xe0, (byte)0x4f, (byte)0x01, (byte)0x56, (byte)0x97, (byte)0xf3, (byte)0xcb, (byte)0x60, (byte)0x5b, (byte)0x84, (byte)0x49, (byte)0x45, (byte)0x3a, (byte)0xe2, (byte)0x0e, (byte)0xd1, (byte)0xbd, (byte)0xc0, (byte)0xa7, (byte)0xe1, (byte)0xfa, (byte)0x82, (byte)0xee, (byte)0x3c, (byte)0x73};
//		privKey.setS(privData, (short) 0, (short) privData.length);
		
		byte[] data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
		
		
		signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
		
		try {
			signature.init(pair.getPrivate(), Signature.MODE_SIGN);
		} catch(CryptoException e) {
			ISOException.throwIt(JCSystem.getVersion());
		}
		byte[] signData = new byte[127];
		short signLen = signature.sign(data, (short) 0, (short) data.length, signData, (short) 0);
//		short sendLen = signature.sign(data, (short) 0, (short) data.length, buffer, (short) 0);
//		apdu.setOutgoingAndSend((short) 0, sendLen);
		
		byte[] certData = new byte[16 + signLen];
		Util.arrayCopyNonAtomic(data, (short) 0, certData, (short) 0, (short) data.length);
		Util.arrayCopyNonAtomic(signData, (short) 0, certData, (short) data.length, signLen);
		signature.init(pair.getPublic(), Signature.MODE_VERIFY);
		if (signature.verify(certData, (short) 0, (short) data.length, signData, (short) 0, signLen)) {
			ISOException.throwIt((short)0x0001);
		} else {
			ISOException.throwIt((short)0x0004);
		}
		apdu.setOutgoingAndSend((short) 0, (short) data.length);
	}
	
	public void encrypt(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		byte[] buffer = apdu.getBuffer();
		mSecretKey = new SecretKeys(SecretKeys.KEY_TYPE_AES);
		byte[] data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
		mSecretKey.keyWrap(data, (short) 0, (short) data.length, buffer, (short) 0, SecretKeys.MODE_ENCRYPT);
//		byte[] data = {0x49, 0x1E, (byte) 0x89, 0x0D, (byte) 0xE9, (byte) 0xAC, (byte) 0xE9, 0x32, (byte) 0x83, (byte) 0x8A, 0x49, 0x79, 0x2F, 0x22, 0x13, (byte) 0xF3};
//		secretKey.keyWrap(data, (short) 0, (short) 16, buffer, (short) 0, SecretKey.MODE_DECRYPT);
		apdu.setOutgoingAndSend((short) 0, (short) 48);
	}
	
	public void AESencrypt(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		byte[] buffer = apdu.getBuffer();
		try {
			// TODO 这里有点问题，没有这个算法？
			mAESKeyInstance = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		} catch(CryptoException e) {
			short reason = e.getReason();
			ISOException.throwIt(reason);
		}
		byte[] keyData = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayFillNonAtomic(keyData, (short) 0, (short) keyData.length, (byte) 0x00);
		mAESKeyInstance.setKey(keyData, (short) 0);
		
		
		byte[] data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
		Cipher cipher = null;
		
		try {
			// Cipher.getInstance在这里过不了，在U2FToken里能过？？？
//			cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
			cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
		} catch (CryptoException e) {
//			ISOException.throwIt(JCSystem.getVersion());
			short reason = e.getReason();
			ISOException.throwIt(reason);
		}
		cipher.init(mAESKeyInstance, Cipher.MODE_ENCRYPT); // 初始向量(iv)是0
//		}
		
		// 加密或解密，doFinal后，cipher对象将被重置
		short sendLen = 0;
		try {
			sendLen = cipher.doFinal(data, (short) 0, (short) data.length, buffer, (short) 0);
		} catch(Exception e) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		apdu.setOutgoingAndSend((short) 0, sendLen);
	}
	
	private byte[] genericTest(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		byte[] test = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
		test[0] = 0x00;
		test[1] = 0x01;
		test[2] = 0x02;
		return test;
	}
	
//	private void decrypt(APDU apdu, byte cla, byte p1, byte p2, short lc) {
//		SecretKeys secreKey = SecretKeys.getInstance(SecretKeys.KEY_TYPE_AES);
//		apdu.setIncomingAndReceive();
//		byte[] buffer = apdu.getBuffer();
//		byte[] data = {0x49, 0x1E, (byte) 0x89, 0x0D, (byte) 0xE9, (byte) 0xAC, (byte) 0xE9, 0x32, (byte) 0x83, (byte) 0x8A, 0x49, 0x79, 0x2F, 0x22, 0x13, (byte) 0xF3};
//		secreKey.keyWrap(data, (short) 0, (short) 16, buffer, (short) 0, SecretKeys.MODE_DECRYPT);
//		apdu.setOutgoingAndSend((short) 0, (short) 16);
//	}
//	public void uninstall() {
//		// TODO Auto-generated method stub
//		SecretKeys.mAESSecretKey = null;
//		SecretKeys.mDESSecretKey = null;
//	}
}
