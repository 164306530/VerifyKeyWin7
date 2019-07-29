# VerifyKeyWin7

不用安装密钥直接利用httprequest检测密钥的激活错误代码.
利用pidgenx.dll的PidGenX函数解码出密钥的各个参数,然后POST激活网址.
目前ProductKeyActConfigId的后面部分不知道由来,不知道是不是跟crypt32.dll的CertAlgIdToOID有关.只知道是12位的数组的BASE64值.

#post
![image](https://github.com/laomms/VerifyKeyWin7/blob/master/win7_01.png)
#ResponseXML Value
![image](https://github.com/laomms/VerifyKeyWin7/blob/master/win7_02.png)

#post
![image](https://github.com/laomms/VerifyKeyWin7/blob/master/win7_1.png)
#ResponseXML Value
![image](https://github.com/laomms/VerifyKeyWin7/blob/master/win7_2.png)

#post
![image](https://github.com/laomms/VerifyKeyWin7/blob/master/win7_3.png)
#ResponseXML Value
![image](https://github.com/laomms/VerifyKeyWin7/blob/master/win7_4.png)

