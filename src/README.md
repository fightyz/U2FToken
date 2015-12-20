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
