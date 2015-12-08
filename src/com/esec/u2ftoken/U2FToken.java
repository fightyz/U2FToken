package com.esec.u2ftoken;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class U2FToken extends Applet {

	/**
	 * 存储attestation证书的二进制文件。FID是EF01
	 */
	public BinaryEF attestationCertFile;
	
	/**
	 * 版本号："U2F_V2"
	 */
	private static final byte version[] = {(byte)0x55, (byte)0x32, (byte)0x46, (byte)0x5F, (byte)0x56, (byte)0x32};
	
	public U2FToken() {
		attestationCertFile = new BinaryEF((byte)0xEF, (byte)0x01); 
	}
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new U2FToken().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			getSelectResponse(apdu);
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0x00:
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

}
