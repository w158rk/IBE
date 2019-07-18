/**!
 * @file handle.c 
 * @author Wang RUikai 
 * @date July 18th, 2019 
 * @brief the plain text handler
 */

#include "base.h"
#include "handle.h"
#include <crypto.h>

#define ISCHAR(c) ((c>='a'&&c<='z') || (c>='A'&&c<='Z'))

int handle_message(unsigned char *m, size_t m_len, FILE *write_file) {
	fprintf(stdout, "decrypted text length : %ld\n", m_len);
	int i;
	printf("the content is:");
	for(i=0; i<m_len; ++i) {
		if(0 == i%4) printf(" ");
		if(0 == i%16) printf("\n");
		
		if(ISCHAR(m[i]))
			printf("%c", m[i]);
		else
			printf("%02x", m[i]);

	}
	printf("\n");
	// do something else

	switch (m[0])
	{
	case 0:
		handle_plaintext(m, m_len, write_file);
		break;

	case 1:
		handle_private_key_request(m, m_len, write_file);
		break;

	case 2:
		handle_private_key_response(m, m_len, write_file);
	
	default:
		break;
	} 
}


int handle_plaintext(unsigned char *m, size_t m_len, FILE *write_file)
{



}

int handle_private_key_request(unsigned char *m, size_t m_len, FILE *write_file)
{

    /*read the id */
    int id_len = *(int *)(m + 1);
    char *id = (char *)malloc(id_len);
    char *p = m+PRIVATE_KEY_REQUEST_HEAD;
    memcpy(id, p, id_len);

    /* calculate the private key */
    SM9MasterSecret *msk = SM9MasterSecret_new();
    get_msk_fp(MSK_FILE, msk);
    SM9PrivateKey *sk = extract_private_key(msk, id);

    char sk_buff[IBE_BUFFER_SIZE];
    BIO *bio = BIO_new_mem_buf(sk_buff, IBE_BUFFER_SIZE);
    

}

int handle_private_key_response(unsigned char *m, size_t m_len, FILE *write_file)
{



}
