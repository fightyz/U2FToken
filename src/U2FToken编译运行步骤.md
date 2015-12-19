在本目录打开命令行，依次运行：  
complie.bat(设置环境变量，用javac编译.class)；  
converter -config converter.cfg(将.class转换成.cap, .jca)；  
scriptgen com\esec\u2ftoken\javacard\u2ftoken.cap -o default.scr(将.cap转换成APDU指令流)
照着default-success-create.scr添加首尾的命令流到default.scr
设置环境变量后，在另一个cmd打开cref -z，模拟器
apdutool default.scr