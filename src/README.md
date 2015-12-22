### 1. 使用jcsdk自带工具
在本目录打开命令行，依次运行：  
complie.bat(设置环境变量，用javac编译.class)；  
converter -config converter.cfg(将.class转换成.cap, .jca)；  
scriptgen com\esec\u2ftoken\javacard\u2ftoken.cap -o default.scr(将.cap转换成APDU指令流)
照着default-success-create.scr添加首尾的命令流到default.scr
设置环境变量后，在另一个cmd打开cref -z，模拟器
apdutool default.scr

### 2. 使用javacard模拟器jcardsim
<https://github.com/licel/jcardsim>  
在本目录打开命令行，依次运行：  
complie-jcardsim-3.0.4(其实就是javac编译，注意这里是用的javacard3.0.4，要使用2.2.2请修改里面的classpath)  
执行 java -cp jcardsim-3.0.4-SNAPSHOT.jar;. com.licel.jcardsim.utils.APDUScriptTool jcardsim.cfg apdu.script

### 3. ECDSA
卡上的公钥pubKey.getW():[每次都不一样] (65byte) 

>04, 00, b9, 8f, cf, c3, c0, ae, 95, 6a, 5b, 12, 6d, be, 43, e4, 7f, 09, 0d, de, 02, d2, 6b, 28, 86, ed, 2b, d7, e2, c2, 69, c1, 89, b2, 53, 96, c1, 2d, bf, 4c, 30, ae, d5, d5, 3c, b5, f9, 3b, 20, 37, 83, 88, 9f, 34, 74, f5, 6c, 97, 1e, 0a, a9, e7, fa, a6, 69
>{0x04, 0x00, (byte)0xb9, (byte)0x8f, (byte)0xcf, (byte)0xc3, (byte)0xc0, (byte)0xae, (byte)0x95, 0x6a, 0x5b, 0x12, 0x6d, (byte)0xbe, 0x43, (byte)0xe4, 0x7f, 0x09, 0x0d, (byte)0xde, 0x02, (byte)0xd2, 0x6b, 0x28, (byte)0x86, (byte)0xed, 0x2b, (byte)0xd7, (byte)0xe2, (byte)0xc2, 0x69, (byte)0xc1, (byte)0x89, (byte)0xb2, 0x53, (byte)0x96, (byte)0xc1, 0x2d, (byte)0xbf, 0x4c, 0x30, (byte)0xae, (byte)0xd5, (byte)0xd5, 0x3c, (byte)0xb5, (byte)0xf9, 0x3b, 0x20, 0x37, (byte)0x83, (byte)0x88, (byte)0x9f, 0x34, 0x74, (byte)0xf5, 0x6c, (byte)0x97, 0x1e, 0x0a, (byte)0xa9, (byte)0xe7, (byte)0xfa, (byte)0xa6, 0x69}

卡上的私钥privKey.getS():(32byte)
>25, c9, ec, dc, 4c, 59, a3, e0, 4f, 01, 56, 97, f3, cb, 60, 5b, 84, 49, 45, 3a, e2, 0e, d1, bd, c0, a7, e1, fa, 82, ee, 3c, 73
>{(byte)0x25, (byte)0xc9, (byte)0xec, (byte)0xdc, (byte)0x4c, (byte)0x59, (byte)0xa3, (byte)0xe0, (byte)0x4f, (byte)0x01, (byte)0x56, (byte)0x97, (byte)0xf3, (byte)0xcb, (byte)0x60, (byte)0x5b, (byte)0x84, (byte)0x49, (byte)0x45, (byte)0x3a, (byte)0xe2, (byte)0x0e, (byte)0xd1, (byte)0xbd, (byte)0xc0, (byte)0xa7, (byte)0xe1, (byte)0xfa, (byte)0x82, (byte)0xee, (byte)0x3c, (byte)0x73}