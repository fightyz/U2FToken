@echo off
set JC_HOME=E:\workspace\java\javacard\java_card_kit-2_2_2-windows\java_card_kit-2_2_2
set JAVA_HOME=E:\workspace\java\javacard\jdk1.5.0_14
set PATH=.;%JC_HOME%\bin;%JAVA_HOME%\bin;%PATH%
set CLASSPATH=.;%JAVA_HOME%\lib\dt.jar;%JAVA_HOME%\lib\tools.jar;