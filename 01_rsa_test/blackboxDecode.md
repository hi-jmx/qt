1.openssl 的库。
	http://slproweb.com/products/Win32OpenSSL.html 选择安装32位的， 安装目录中的lib及include可用
2.pro中添加库文件及库的头文件

3.rsa加解密 （rsa 1024）
	1.注意事项：
		1.加密时 读取(1028/8-11)对uchar 数组进行加密
		2.解密时 读取（1024/8） 对uchar数组进行解密
		3.公钥、私钥要带着头，换行，尾复制过去，否则会失败
		4.一般是公钥加密，私钥解密，加密之后的密文是不一样的
		5.也可以私钥加密，公钥解密，但是加密之后的密文是一样的，
		6.有些项目对密文或者key转成了base64格式，这个项目都未转，
		7.对接java项目时，加解密的配置一定要一样，使用RSA/None/PCS1Padding 的填充方式