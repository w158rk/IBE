

#ifndef CONFIG__H
#define CONFIG__H

/* used files */

#define MSK_FILE                "msk.conf"


/* buffer sizes */
#define BUFFER_SIZE             1024
#define SECURITY_BITS           256
#define MAX_ID_LEN              (SECURITY_BITS/8)
#define IBE_BUFFER_SIZE         128


/* server parameters */
#define LISTEN_BACKLOG          50

#define SERVER_ID              "Server"
#define SERVER_ID_LEN           6
#define SERVER_IP_ADDRESS       "127.0.0.1"
#define SERVER_LISTEN_PORT      5001
#define SERVER_RUN_PORT         5002

/* key lengths */
#define AES_KEY_BITS            256 
#define AES_KEY_LEN             (AES_KEY_BITS/8)


/* application protocol */

#define PLAIN_MESSAGE_TYPE          0

#define PRIVATE_KEY_REQUEST_TYPE    1
#define PRIVATE_KEY_REQUEST_HEAD    5           /* the length of the head */
#define PRIVATE_KEY_RESPONSE_TYPE   1
#define PRIVATE_KEY_RESPONSE_HEAD   1

#endif


