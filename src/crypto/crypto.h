#ifndef CRYPTO_H
#define CRYPTO_H 

int system_setup(const char* mpk_filename, const char* msk_filename);
SM9PrivateKey* extract_private_key(SM9MasterSecret* msk, const char* id);
int sm9_encrypt(const unsigned char* data, size_t data_len, unsigned char* c_buf, size_t *c_len, 
    SM9PublicParameters *mpk, const char *id, size_t id_len);
int sm9_decrypt(const unsigned char* c_buf, size_t c_len, unsigned char* m_buff, size_t *m_len, 
    SM9PrivateKey *sk);

int get_mpk_fp(const char* mpk_filename, SM9PublicParameters* mpk);
int get_msk_fp(const char* msk_filename, SM9MasterSecret* msk);
int get_sk_fp(const char* sk_filename, SM9PrivateKey* sk);

int put_sk_fp(const char* sk_filename, SM9PrivateKey* sk);

#endif 