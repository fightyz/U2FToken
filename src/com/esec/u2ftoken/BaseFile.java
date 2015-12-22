package com.esec.u2ftoken;
/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-7 下午09:31:38 
 * 所有文件的基类
 */
public class BaseFile {
	public static final byte FILE_TYPE_BINARY = 0x02; // 二进制文件
	public static final byte FILE_TYPE_FIXED_LENGTH = 0x03; // 定长记录文件
	
	/**
	 * 文件FID的高字节
	 */
	public byte mFID;
	
	/**
	 * 文件的SFI值
	 */
	public byte mSFI;
}
