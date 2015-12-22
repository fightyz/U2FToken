package com.esec.u2ftoken;
/** 
 * @author Yang Zhou 
 * @version 创建时间：2015-12-7 下午09:36:38 
 * Transparent structure.
 */
public class BinaryEF extends BaseFile {
	/**
	 * 保存二进制文件实体的byte数组
	 */
	private byte mFileContent[];
	
	/**
	 * 用FID初始化二进制文件
	 * @param FID 文件FID的高字节
	 * @param SFI 文件FID的低字节（也是SFI）
	 */
	public BinaryEF(byte FID, byte SFI) {
		mFID = FID;
		mSFI = SFI;
	}
	
	/**
	 * 动态给二进制文件分配空间
	 * @param size 分配空间大小
	 */
	public void createBinaryContent(short size) {
		//TODO 可能会有最大空间限制
		mFileContent = new byte[size];
	}
	
	/**
	 * 用一个字节数组设置该二进制文件实体
	 * @param mContent 传入的二进制文件实体
	 */
	public void setFileContent(byte[] mContent) {
		mFileContent = mContent;
	}
	
	/**
	 * 获得该二进制文件实体
	 * @return 二进制文件实体的字节数组
	 */
	public byte[] getFileContent() {
		return mFileContent;
	}
}
