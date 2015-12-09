//package org.esec.mcg.utils;
/**
 * java CertToHardString cert.der
 * 将DER编码的二进制证书文件转换成字符串：(byte)0x01, (byte)0x02...
 * 主要是方便将其写死到代码里。。。
 * 需要放在包org.esec.mcg.utils下，将FileUtil.java，ByteUtil.java中的package包申明注释掉
 * (否则，如果不能单独编译这两个文件，而是需要编译整个包的所有文件)
 * javac FileUtile.java ByteUtil.java
 * javac CertToHardString.java
 * java CertToHardString cert.der
 * 输出的字符串保存在out.txt中
 */
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class CertToHardString {
	public static void main(String[] args) {
		File file = new File(args[0]);
		byte[] result = FileUtil.FileToByteArray(file);
		String s = ByteUtil.ByteArrayToHexString(result);
		StringBuilder sb = new StringBuilder();
		sb.append("(byte)");
		int len = s.length();
		for (int i = 0; i < len; i++ ) {
			char c = s.charAt(i);
			if(c == ' ') {
				sb.append(", (byte)0x");
			} else {
				sb.append(c);
			}
		}
		// System.out.println(sb.toString());
		FileWriter fw;
		try {
			File outFile = new File("out.txt");
			fw = new FileWriter(outFile);
			fw.write(sb.toString());
			fw.flush();
		} catch(IOException e) {
			e.printStackTrace();
		}
		
		
	}
}