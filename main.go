package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/google/go-attestation/attest"
)

func main() {
	// 1. 打开 TPM（Windows 下内部通过 TBS 接口）
	tpm, err := attest.OpenTPM(&attest.OpenConfig{}) // nil 也可
	if err != nil {
		log.Fatalf("OpenTPM: %v", err)
	}
	defer tpm.Close()

	// 2. 输出厂商、固件版本等基本信息
	info, err := tpm.Info()
	if err != nil {
		log.Fatalf("Info: %v", err)
	}
	fmt.Printf("TPM 厂商: %s  接口: %v\n",
		info.Manufacturer, info.Interface)

	// 3. 枚举 Endorsement Key，通常至少一把 RSA EK 
	eks, err := tpm.EKs()
	if err != nil {
		log.Fatalf("EKs: %v", err)
	}
	fmt.Printf("枚举到 %d 条 EK\n", len(eks))

	// 4. 生成一把新的 Attestation Key（存于 TPM 内部）
	ak, err := tpm.NewAK(&attest.AKConfig{})
	if err != nil {
		log.Fatalf("NewAK: %v", err)
	}
	defer ak.Close(tpm)

	// 5. 对 PCR[0,7] 生成 Quote，附带 32 字节随机 nonce
	nonce := sha256.Sum256([]byte("go-attestation example"))
	quote, err := ak.QuotePCRs(tpm, nonce[:20], attest.HashSHA256, []int{0, 7})
	if err != nil {
		log.Fatalf("QuotePCRs: %v", err)
	}
	fmt.Printf("Quote 签名长度: %d 字节\n", len(quote.Signature))
	fmt.Printf("Quote.Signature (hex): %s\n", hex.EncodeToString(quote.Signature))

	// 6. 可根据需要把 quote、AK 公钥、EK 公钥发给远端验证
}
