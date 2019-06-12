# 密码学API 

将GmSSL中的函数封装为新系统需要的函数 

## SM9 

### 数据结构 

```c
SM9PublicParameters *mpk = NULL;            // public master key
SM9MasterSecret *msk = NULL;                // master key 
SM9PrivateKey *sk = NULL;                   // private key
```

### 加密解密算法 

```c
SM9_setup(NID_sm9bn256v1, NID_sm9encrypt, NID_sm9hash1_with_sm3, &mpk, &msk)
sk = SM9_extract_private_key(msk, id, strlen(id))
SM9_encrypt(NID_sm9encrypt_with_sm3_xor, data, datalen,
		cbuf, &clen, mpk, id, strlen(id))
SM9_decrypt(NID_sm9encrypt_with_sm3_xor, cbuf, clen,
		mbuf, &mlen, sk)
```

### I/O 接口

```c
SM9_wrap_key(NID_sm9kdf_with_sm3, key, sizeof(key), C, &Clen, mpk, id, strlen(id))
SM9_unwrap_key(NID_sm9kdf_with_sm3, key2, sizeof(key2), C, sizeof(C), sk)

SM9MasterSecret *d2i_SM9MasterSecret_fp(FILE *fp, SM9MasterSecret **pp);
SM9PublicParameters *d2i_SM9PublicParameters_fp(FILE *fp, SM9PublicParameters **pp);
SM9PrivateKey *d2i_SM9PrivateKey_fp(FILE *fp, SM9PrivateKey **pp);
SM9Signature *d2i_SM9Signature_fp(FILE *fp, SM9Signature **pp);
SM9Ciphertext *d2i_SM9Ciphertext_fp(FILE *fp, SM9Ciphertext **pp);

int i2d_SM9MasterSecret_fp(FILE *fp, SM9MasterSecret *a);
int i2d_SM9PublicParameters_fp(FILE *fp, SM9PublicParameters *a);
int i2d_SM9PrivateKey_fp(FILE *fp, SM9PrivateKey *a);
int i2d_SM9Signature_fp(FILE *fp, SM9Signature *a);
int i2d_SM9Ciphertext_fp(FILE *fp, SM9Ciphertext *a);
```

## AES 

```c
AES_cbc_encrypt(buf, buf, (size_t)lengths[testnum], &aes_ks3, iv, AES_ENCRYPT);
```