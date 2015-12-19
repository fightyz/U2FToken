1. delete一个module时，返回6448：
>cm>  delete A0000006472F0001  
 => 84 E4 00 00 12 4F 08 A0 00 00 06 47 2F 00 01 88    .....O.....G/...  
    CC 45 41 D5 0E DB D5 00                            .EA.....  
 (47017 usec)  
 <= 64 48                                              dH  
Status: 0x6448  
jcshell: Error code: 6448 (0x6448)  
jcshell: Wrong response APDU: 6448  

这时用命令 delete -r A0000006472F00(Package AID)，这将会删除load file和any associated instance

会出现这个删不掉的原因是：The JCRE is unable to remove an applet if there are reference to static variables. The correct solution to this is to make your applet implement the AppletEvent interface and in the public void uninstall() method, set the variable to null.

    /* (non-Javadoc)
     * @see javacard.framework.AppletEvent#uninstall()
     */
    public void uninstall() {
        baData = null;
    }