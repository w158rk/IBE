/**
 * @file base.c 
 * @author Wang Ruikai 
 * @date July 14th, 2019
 * @brief This file contains wrapper functions and facility functions used  
 *      in both client and server
 */
#include "base.h"


int receive_ibe(unsigned char *m, size_t *m_len, 
                 const char *id, FILE *read_file) 
{

	char len_str[5] = {'\0'};				// 长度
	unsigned int c_len;
	char *c;
	if (-1 == fread(len_str, sizeof(char), 4, read_file)) {				//把read_file中的内容读入len_str
		fprintf(stderr, "read IBE cipher length error\n");
		return -1;
	}

	// 字符转整数 - 网络序转机器序 
	c_len = *(int *)len_str;
	c_len = ntohl(c_len);
	c = (char *) malloc(c_len);

	// 读0
	if (-1 == fread(c, sizeof(char), CRYPTO_HEAD_LEN-IBE_HEAD_LEN, read_file)) {
		fprintf(stderr, "read IBE cipher length error\n");
		return -1;
	}			

	// read cipher
	if (-1 == fread(c, sizeof(char), c_len, read_file)) {
		fprintf(stderr, "read IBE cipher error with lengh %d\n", c_len);
		return -1;
	}

	// make the private key filename 
	char temp[20] = "sk_";
	int id_len = strlen(id)>16 ? 16 : strlen(id);  
	memcpy(temp+3, id, id_len);
	char *sk_filename = strcat(temp, ".conf");

	// read private key
	SM9PrivateKey *sk = SM9PrivateKey_new();
	if (-1 == get_sk_fp(sk_filename, sk)) {
		fprintf(stderr, "read IBE private key error with filename : %s\n", sk_filename);
		return -1;
	}

	// decrypt
	if (-1 == sm9_decrypt(c, c_len, m, m_len, sk)) {
		fprintf(stderr, "IBE decrypt fails\n");
		return -1;
	}

}

int send_ibe(unsigned char *m, size_t m_len, const char* id,
                size_t id_len, FILE *write_file)
{

      	// 加密 
	char c[BUFFER_SIZE];
	size_t c_len;

	SM9PublicParameters *mpk = SM9PublicParameters_new();

	if (-1 == get_mpk_fp(MPK_FILENAME, mpk)) {
		fprintf(stderr, "read mpk fails\n");
		return -1;
	}

	if (-1 == sm9_encrypt(m, m_len, 
                    c, &c_len, mpk, id, id_len) ) 
        {
		fprintf(stderr, "encrypt error\n");
		return -1;
	}

	// 做包，加头 
	int packet_len = CRYPTO_HEAD_LEN + c_len;
	char *packet = (char *)malloc(packet_len);
	memcpy(packet+CRYPTO_HEAD_LEN, c, c_len);
	c_len = htonl(c_len);
	char *len_str = (char *)&c_len;
	memcpy(packet+1, len_str, 4);
	packet[0] = CRYPTO_IBE;

	// 发送 
	Write(fileno(write_file), packet, packet_len);


}

int receive_aes(unsigned char *m, size_t *m_len, 
                FILE *read_file, unsigned char* aes_key) 
{

	char iv[AES_IV_LEN];
	char *c;
	char len_str[5] = {'\0'};

	unsigned int c_len;

	// 读取IV
	if (-1 == fread(iv, 1, AES_IV_LEN, read_file)) {
		fprintf(stderr, "read AES iv error \n");
		return -1;
	}

	if (-1 == fread(len_str, sizeof(char), 4, read_file)) {
		fprintf(stderr, "read AES cipher length error\n");
		return -1;
	}

	// 字符转整数 - 网络序转机器序 
	int *len_p = (int *)len_str; 
	c_len = *len_p;
	c_len = ntohl(c_len) - CRYPTO_HEAD_LEN;
	c = (char *) malloc(c_len);

	// 读0
	if (-1 == fread(c, sizeof(char), CRYPTO_HEAD_LEN-IBE_HEAD_LEN, read_file)) {
		fprintf(stderr, "read IBE cipher length error\n");
		return -1;
	}			

	// read cipher
	if (-1 == fread(c, sizeof(char), c_len, read_file)) {
		fprintf(stderr, "read AES cipher error with lengh %d\n", c_len);
		return -1;
	}

	// 解密
	if (-1 == cbc_decrypt(c, c_len, aes_key, iv, m, m_len)) {
		fprintf(stderr, "aes decrypt error\n");
		return -1;
	}
}

