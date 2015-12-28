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
	
	private static ECPrivateKey attestationPrivateKey;
	private static boolean attestationCertificateSet;
	private static boolean attestationPrivateKeySet;
	
	private static final byte P1_CONTROL_CHECK_ONLY = 0x07;
	private static final byte P1_CONTROL_SIGN = 0x03;
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
	
	private static final byte CLA_7816 = 0x00;
	private static final byte CLA_U2F = 0x00;
	private static final byte CLA_PROPRIETARY = (byte)0xF0;
	
	private static final byte INS_ISO_GET_DATA = (byte)0xC0;
	private static final byte INS_SET_ATTESTATION_CERT = 0x01;
	private static final byte INS_SET_ATTESTATION_PRIVATE_KEY = 0x02;
	
	public static final byte INS_TEST_ENCRYPT = 0x10;
	public static final byte INS_TEST_DECRYPT = 0x20;
	public static final byte INS_TEST_SEEECPUBKEY = 0x30;
	public static final byte INS_TEST_VERIFY = 0x40;
	public static final byte INS_TEST_BOUNCY_CASTLE = 0x50;
	public static final byte INS_TEST_GENERIC = 0x60;
	
	private static final byte INS_U2F_REGISTER = 0x01; // Registration command
	private static final byte INS_U2F_AUTHENTICATE = 0x02; // Authenticate/sign command
	private static final byte INS_U2F_VERSION = 0x03; //Read version string command
	private static final byte INS_U2F_CHECK_REGISTER = 0x04; // Registration command that incorporates checking key handles
	private static final byte INS_U2F_AUTHENTICATE_BATCH = 0x05; // Authenticate/sign command for a batch of key handles
	
	public static final short U2F_SW_TEST_OF_PRESENCE_REQUIRED = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
	
	private static final short ATTESTATION_SIGNATURE_SIZE = 75;
	
	private static final byte[] VERSION = {'U', '2', 'F', '_', 'V', '2'};
	
//	private static final byte[] ATTESTATION_CERTIFICATE = {0x30, (byte)0x82, 0x01, 0x15, 0x30, (byte)0x81, (byte)0xbc, 0x02, 0x09, 0x00, (byte)0xc5, (byte)0xf4, (byte)0xee, 0x4c, 0x59, 0x50, 0x3e, 0x05, 0x30, 0x0a, 0x06, 0x08, 0x2a, (byte)0x86, 0x48, (byte)0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x59, 0x61, 0x6e, 0x67, 0x5a, 0x68, 0x6f, 0x75, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35, 0x31, 0x32, 0x30, 0x39, 0x30, 0x37, 0x30, 0x34, 0x35, 0x38, 0x5a, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x32, 0x30, 0x38, 0x30, 0x37, 0x30, 0x34, 0x35, 0x38, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08, 0x59, 0x61, 0x6e, 0x67, 0x5a, 0x68, 0x6f, 0x75, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, (byte)0x86, 0x48, (byte)0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, (byte)0x86, 0x48, (byte)0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x72, (byte)0x9a, 0x71, (byte)0xd0, (byte)0x81, 0x62, 0x42, (byte)0x84, (byte)0x92, (byte)0xf2, (byte)0xd9, 0x61, (byte)0x92, 0x4d, 0x37, 0x44, 0x3a, 0x4f, 0x1b, (byte)0xda, 0x58, 0x0f, (byte)0x8a, (byte)0xea, 0x29, 0x20, (byte)0xd2, (byte)0x99, 0x7c, (byte)0xbe, (byte)0xa4, 0x39, 0x60, (byte)0xce, 0x72, (byte)0x9e, 0x35, (byte)0xc1, (byte)0xf7, 0x40, (byte)0x92, (byte)0xf2, 0x25, 0x0e, 0x60, 0x74, (byte)0x82, 0x3f, (byte)0xc5, 0x7f, 0x33, 0x60, (byte)0xb7, (byte)0xcd, 0x39, 0x69, (byte)0xc3, (byte)0xc3, 0x12, 0x5e, (byte)0xce, 0x26, 0x5c, 0x29, 0x30, 0x0a, 0x06, 0x08, 0x2a, (byte)0x86, 0x48, (byte)0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, (byte)0xe7, 0x67, (byte)0xfa, (byte)0x94, 0x10, 0x35, (byte)0xd5, (byte)0x85, 0x3d, 0x52, (byte)0xd8, 0x7d, 0x67, 0x14, 0x70, (byte)0xbc, 0x76, 0x3b, (byte)0xc5, (byte)0xb1, 0x2e, 0x1d, 0x45, 0x77, (byte)0xea, (byte)0x9f, (byte)0x8c, (byte)0xa6, 0x74, (byte)0xe5, (byte)0x9d, 0x39, 0x02, 0x20, 0x3f, (byte)0xe1, 0x1c, (byte)0xad, 0x59, (byte)0xf5, 0x35, 0x76, 0x00, 0x1f, 0x15, (byte)0xee, 0x05, (byte)0xda, (byte)0x87, 0x46, (byte)0xfe, (byte)0xd3, 0x27, 0x6b, 0x16, (byte)0x82, (byte)0x9e, (byte)0x9d, 0x5e, (byte)0xfd, (byte)0xff, 0x70, 0x5e, 0x08, (byte)0x9c, 0x6d};
//	private static final byte[] ATTESTATION_PRIVATE_KEY = {0x4c, (byte)0xc7, (byte)0xcf, 0x68, (byte)0x91, 0x18, (byte)0x96, (byte)0xc8, (byte)0xe2, (byte)0xf9, (byte)0xc8, (byte)0xcc, 0x2f, 0x7f, 0x0a, (byte)0xa2, 0x1c, 0x6a, (byte)0xcb, (byte)0xba, 0x38, 0x1c, 0x10, (byte)0x9a, (byte)0xfe,(byte)0x91, 0x18, (byte)0xf6, (byte)0xca, (byte)0xd9, 0x0f, 0x0b};
	private static byte[] ATTESTATION_CERTIFICATE;
	
	public SecretKeys mSecretKey;
	private AESKey mAESKeyInstance;
	
	private KeyPair pair;
	private boolean GENED = false;
	private static Signature signature;
	
	private static Signature attestationSignature;
	private static Signature authenticateSignature;
	/**
	 * To store the attestation signature so that it can be handled by GetData
	 */
	private static byte[] signatureMessage;
	
	private static byte[] registerResponse;
	
	private KeyHandleGenerator mKeyHandleGenerator;
	
	private static byte[] counter;
	
	private static boolean counterOverflowed;
	
	public U2FToken() {
		counter = new byte[4];
		signatureMessage = JCSystem.makeTransientByteArray(ATTESTATION_SIGNATURE_SIZE, JCSystem.CLEAR_ON_DESELECT);
		
		mKeyHandleGenerator = new IndexKeyHandle();
		
		attestationSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
		authenticateSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
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
		
		if (cla == CLA_PROPRIETARY) {
			if (attestationCertificateSet && attestationPrivateKeySet) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
			switch (buf[ISO7816.OFFSET_INS]) {
			case INS_SET_ATTESTATION_CERT:
				setAttestationCert(apdu, cla, p1, p2, lc);
				break;
			case INS_SET_ATTESTATION_PRIVATE_KEY:
				setAttestationPrivateKey(apdu, cla, p1, p2, lc);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		} else if (cla == CLA_U2F) {
			if (!attestationCertificateSet || !attestationPrivateKeySet) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
			switch (buf[ISO7816.OFFSET_INS]) {
			case (byte) INS_TEST_ENCRYPT:
//				try {
//					KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
//				} catch(CryptoException e) {
//					short reason = e.getReason();
////					ISOException.throwIt(JCSystem.getVersion());
////					ISOException.throwIt(reason);
//				}
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
//				decrypt(apdu, cla, p1, p2, lc);
				break;
			case (byte) INS_U2F_REGISTER: // U2F register command
				u2fRegister(apdu, cla, p1, p2, lc);
				break;
				
			case (byte) INS_U2F_AUTHENTICATE: // U2F authenticate command
				u2fAuthenticate(apdu, cla, p1, p2, lc);
				break;
			
			case (byte) INS_ISO_GET_DATA:
				getData(apdu, cla, p1, p2, lc);
				
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
		} else {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}
	
	/**
	 * When select this Applet, return version: "U2F_V2".
	 * @param apdu
	 */
	private void getSelectResponse(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopyNonAtomic(VERSION, (short)0, buffer, (short)0, (short)VERSION.length);
		apdu.setOutgoingAndSend((short)0, (short)VERSION.length);
	}
	
	private void setAttestationCert(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		ATTESTATION_CERTIFICATE = new byte[len];
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, ATTESTATION_CERTIFICATE, (short) 0, len);
		attestationCertificateSet = true;
	}
	
	private void setAttestationPrivateKey(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		short len = apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
//		attestationPrivateKey = (ECPrivateKey) KeyBuilder.buildkey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
//		SecP256r1.setCurveParameters(attestationPrivateKey);
		attestationPrivateKey = (ECPrivateKey)SecP256r1.newKeyPair().getPrivate();
		attestationPrivateKey.setS(buffer, ISO7816.OFFSET_CDATA, len);
		attestationSignature.init(attestationPrivateKey, Signature.MODE_SIGN);
		attestationPrivateKeySet = true;
	}

	/**
	 * Pull registration request message. Generate registration response message. 
	 * @param apdu
	 * @param cla 0x00
	 * @param p1 
	 * @param p2
	 * @param lc
	 */
	private void u2fRegister(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		short readCount = apdu.setIncomingAndReceive();		
		if (readCount != LEN_REGISTRATION_REQUEST_MESSAGE) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		byte[] buffer = apdu.getBuffer();
		SharedMemory sharedMemory = SharedMemory.getInstance();
		
		byte[] challengeSha256 = sharedMemory.m32BytesChallengeSha256;
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, challengeSha256, (short) 0, LEN_CHALLENGESHA256);
		
		byte[] applicationSha256 = sharedMemory.m32BytesApplicationSha256;
		Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA + LEN_CHALLENGESHA256),
				applicationSha256, (short) 0, LEN_APPLICATIONSHA256);
		
		// Generate user authentication key
		KeyPair userKeyPair = SecP256r1.newKeyPair();
		userKeyPair.genKeyPair();
		ECPrivateKey privKey = (ECPrivateKey)userKeyPair.getPrivate();
		ECPublicKey pubKey = (ECPublicKey)userKeyPair.getPublic();
		
		// Store user's private key locally. Generate Key Handle.
		byte[] keyHandle = mKeyHandleGenerator.generateKeyHandle(applicationSha256, privKey);
		
		byte[] userPublicKey = sharedMemory.m65BytesUserPublicKey;
		pubKey.getW(userPublicKey, (short) 0);
		
		// Sign data
		byte[] signedData = RawMessageCodec.encodeRegistrationSignedBytes(
				applicationSha256,
				challengeSha256,
				keyHandle,
				userPublicKey
				);
		
		// Generate signature use attestation private key
		short signLen = attestationSignature.sign(signedData, (short) 0, (short) signedData.length, signatureMessage, (short) 2);
		Util.setShort(signatureMessage, (short) 0, signLen);
		
		// Generate register response
		registerResponse = RawMessageCodec.encodeRegisterResponse(userPublicKey, keyHandle, ATTESTATION_CERTIFICATE, signatureMessage);
		Util.setShort(registerResponse, (short) 1, (short) 259);
		Util.arrayCopyNonAtomic(registerResponse, (short) 3, buffer, (short) 0, (short)256);
		
		apdu.setOutgoingAndSend((short) 0, (short) 256);
		if ((short)(registerResponse.length - 259) > 256) {
			ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
		} else if ((short)(registerResponse.length - 259) != 0) {
			ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00 + registerResponse.length - 259));
		}
	}
	
	private void getData(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		byte[] buffer = apdu.getBuffer();
		short length = lc;
		if (length == 0) {
			short sendOffset = Util.makeShort(registerResponse[1], registerResponse[2]);
			Util.arrayCopyNonAtomic(registerResponse, sendOffset, buffer, (short) 0, (short) 256);
			sendOffset += 256;
			Util.setShort(registerResponse, (short) 1, sendOffset);
			apdu.setOutgoingAndSend((short) 0, (short) 256);
			short len = (short)(registerResponse.length - sendOffset);
			len = len > 256 ? ISO7816.SW_BYTES_REMAINING_00 : (short)(ISO7816.SW_BYTES_REMAINING_00 + len);
			ISOException.throwIt(len);
		} else if (length > 0) {
			short sendOffset = Util.makeShort(registerResponse[1], registerResponse[2]);
			short len = (short)(registerResponse.length - sendOffset);
			Util.arrayCopyNonAtomic(registerResponse, sendOffset, buffer, (short) 0, len);
			apdu.setOutgoingAndSend((short) 0, len);
		}
	}
	
	private void u2fAuthenticate(APDU apdu, byte cla, byte p1, byte p2, short lc) {
		
		if (counterOverflowed) {
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		}
		
		apdu.setIncomingAndReceive();
		byte[] buffer = apdu.getBuffer();
		SharedMemory sharedMemory = SharedMemory.getInstance();
		
		boolean sign = false;
		byte control = p1;
		switch(control) {
		case (byte) P1_CONTROL_CHECK_ONLY:
			break;
		case (byte) P1_CONTROL_SIGN:
			sign = true;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		byte[] challengeSha256 = sharedMemory.m32BytesChallengeSha256;
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, challengeSha256, (short) 0, LEN_CHALLENGESHA256);
		
		byte[] applicationSha256 = sharedMemory.m32BytesApplicationSha256;
		Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA + LEN_CHALLENGESHA256),
				applicationSha256, (short) 0, LEN_APPLICATIONSHA256);
		
		// Verify Key Handle
		short keyHandleLen = (short) (buffer[(short) ISO7816.OFFSET_CDATA + 64] & 0x00ff);
		byte[] keyHandle = JCSystem.makeTransientByteArray(keyHandleLen, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA + 64 + 1), keyHandle, (short) 0, keyHandleLen);
		ECPrivateKey privKey = mKeyHandleGenerator.verifyKeyHandle(keyHandle);
		
		if (!sign) {
			ISOException.throwIt(U2F_SW_TEST_OF_PRESENCE_REQUIRED);
		}
		
		// Increase the counter
        boolean carry = false;
        JCSystem.beginTransaction();
        for (byte i=0; i<4; i++) {
            short addValue = (i == 0 ? (short)1 : (short)0);
            short val = (short)((short)(counter[(short)(4 - 1 - i)] & 0xff) + addValue);
            if (carry) {
                val++;
            }
            carry = (val > 255);
            counter[(short)(4 - 1 - i)] = (byte)val;
        }
        JCSystem.commitTransaction();
        if (carry) {
            // Game over
            counterOverflowed = true;
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        
        // Authentication response
        byte userPresence = 0x01;
        byte[] signedData = RawMessageCodec.encodeAuthenticationSignedBytes(
        		applicationSha256,
        		userPresence, 
        		counter, 
        		challengeSha256);
        short outOffset = 0;
        buffer[outOffset++] = userPresence;
        outOffset = Util.arrayCopyNonAtomic(counter, (short) 0, buffer, outOffset, (short) 4);
        authenticateSignature.init(privKey, Signature.MODE_SIGN);
        outOffset += authenticateSignature.sign(signedData, (short) 0, (short) 69, buffer, outOffset);
        apdu.setOutgoingAndSend((short) 0, outOffset);
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
			cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
			// cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
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
