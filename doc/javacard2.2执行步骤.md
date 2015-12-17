1. 由于javacard2.2中的converter是识别java sdk1.5所编译的.class文件，因此先打开一个cmd，运行javacard_env.bat设置java和javacard的环境变量
2. 执行
>javac -g -classpath .\classes;..\lib\api.jar;..\lib\installer.jar
src\com\sun\javacard\samples\HelloWorld\\*.java
编译出HelloWorld的class文件
3. 编写converter.cfg文件：
>-out CAP -exportpath ..\\..\api_export_files\ -applet 0xa0:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x1:0x1 com.sun.javacard.samples.HelloWorld.HelloWorld com.sun.javacard.samples.HelloWorld 0xa0:0x0:0x0:0x0:0x62:0x3:0x1:0xc:0x1 1.0
  
其中api_export_files是javacard SDK带的，-applet 后跟applet的AID和实现Applet接口的文件，之后是Package和Package的AID。**注意Applet AID前面部分必须和Package AID一样**

4. 执行将converter.cfg放到项目适当目录，执行converter -config converter.cfg，执行完成后就会在项目Package根目录创建一个javacard文件夹，其中有生成的cap文件
5. 打开jcop的eclipse，执行以下命令与卡进行建连：
>/term "winscard:4|SCM Microsystems Inc. SDI011G Contactless Reader 0"
>/card -a a000000003000000 -c com.ibm.jc.CardManager
>set-key 255/1/DES-ECB/404142434445464748494a4b4c4d4e4f 255/2/DES-ECB/404142434445464748494a4b4c4d4e4f 255/3/DES-ECB/404142434445464748494a4b4c4d4e4f
>init-update 255
>ext-auth mac
>upload "E:\workspace\java\javacard\java_card_kit-2_2_2-windows\java_card_kit-2_2_2\samples\src\com\sun\javacard\samples\HelloWorld\javacard\HelloWorld.cap"
>insatall a00000006203010c01 a00000006203010c0101
>/select A00000006203010C0101

其中install命令后分别跟Package AID和Applet AID