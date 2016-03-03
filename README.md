# U2FToken
An U2F Token implementation based on JavaCard

### Install
1. Complie this Applet and upload to the JavaCard(>3.0)
2. Set the attestation certificate(with Extended APDU):   
> /send f0010000000119308201153081bc020900c5f4ee4c59503e05300a06082a8648ce3d04030230133111300f0603550403130859616e675a686f75301e170d3135313230393037303435385a170d3136313230383037303435385a30133111300f0603550403130859616e675a686f753059301306072a8648ce3d020106082a8648ce3d03010703420004729a71d08162428492f2d961924d37443a4f1bda580f8aea2920d2997cbea43960ce729e35c1f74092f2250e6074823fc57f3360b7cd3969c3c3125ece265c29300a06082a8648ce3d0403020348003045022100e767fa941035d5853d52d87d671470bc763bc5b12e1d4577ea9f8ca674e59d3902203fe11cad59f53576001f15ee05da8746fed3276b16829e9d5efdff705e089c6d
3. Set the attestation private key:  
> /send f0020000#(4cc7cf68911896c8e2f9c8cc2f7f0aa21c6acbba381c109afe9118f6cad90f0b)

### U2F Self-Comformance Test
* Please access the NFC self-conformance test tool here:  <https://github.com/google/u2f-ref-code/tree/master/u2f-tests/NFC>
* Download the newly Android Google Authenticator
* Open <https://crxjs-dot-u2fdemo.appspot.com/> or <https://demo.yubico.com/u2f>
* Do the Register and Authenticate

### Some Tips For Implementation
1. The authenticate private key is stored in the SE, as there is enough memory to hold thousands of keys.
2. The key handle consists with index(first 2 bytes) of the authenticate private key and Sha-256 appid(left 32 bytes)

**//TODO**
1. The database which stores anthenticate private keys can not increase dynamicly now.  
2. I also want to implement a "wrapped" key handle rather than storing the authenticate private key locally in SE.
