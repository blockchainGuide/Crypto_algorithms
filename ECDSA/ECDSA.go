func main() {
	//生成签名----
	//声明明文
	message := []byte("hello world")
	//生成私钥
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//生成公钥
	pub := privateKey.PublicKey
	//将明文散列
	digest := sha256.Sum256(message)
	//生成签名
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	//设置私钥的参数类型为曲线类型
	param := privateKey.Curve.Params()
	//获得私钥byte长度
	curveOrderByteSize := param.P.BitLen() / 8
	//获得签名返回值的字节
	rByte, sByte := r.Bytes(), s.Bytes()
	//创建数组
	signature := make([]byte, curveOrderByteSize*2)
	//通过数组保存了签名结果的返回值
	copy(signature[curveOrderByteSize-len(rByte):], rByte)
	copy(signature[curveOrderByteSize*2-len(sByte):], sByte)

	//验证----
	//将明文做hash散列，为了验证的内容对比
	digest = sha256.Sum256(message)
	curveOrderByteSize = pub.Curve.Params().P.BitLen() / 8
	//创建两个整形对象
	r, s = new(big.Int), new(big.Int)
	//设置证书值
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	//验证
	e := ecdsa.Verify(&pub, digest[:], r, s)
	if e == true {
		fmt.Println("success")
	} else {
		fmt.Println("failed")
	}
}