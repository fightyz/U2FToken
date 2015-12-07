package com.esec.u2ftoken;
/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-7 下午09:36:38 
 * 二进制文件类
 */
public class BinaryEF extends BaseFile {
	/**
	 * 保存二进制文件实体的byte数组
	 */
	public byte mFileContent[];
	
	/**
	 * 用FID初始化二进制文件
	 * @param FID 文件FID的高字节
	 * @param SFI 文件FID的低字节（也是SFI）
	 */
	public BinaryEF(byte FID, byte SFI) {
		mFID = FID;
		mSFI = SFI;
	}
}
