

#ifndef CONFIG__H
#define CONFIG__H

/* used files */

#define MPK_FILENAME        "mpk.conf"
#define MSK_FILENAME        "msk.conf"


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
#define SERVER_LISTEN_PORT      5003
#define SERVER_RUN_PORT         5004    

#define CLIENT_ID              "Client"
#define CLIENT_ID_LEN           6
#define CLEINT_IP_ADDRESS       "127.0.0.1"
#define CLIENT_LISTEN_PORT      16001
#define CLIENT_RUN_PORT         16002

/* application protocol */

#define PLAIN_MESSAGE_TYPE          0
#define PRIVATE_KEY_REQUEST_TYPE    1
#define PRIVATE_KEY_RESPONSE_TYPE   2
#define SESSION_KEY_REQUEST_TYPE    3
#define SESSION_KEY_ACK_TYPE        4
#define SESSION_KEY_FINAL_TYPE      5

#define PRIVATE_KEY_REQUEST_HEAD    5           /* the length of the head */
#define PRIVATE_KEY_RESPONSE_HEAD   1

/** security protocol */
#define NO_ENC_TYPE                 0
#define IBE_TYPE                    1 
#define AES_TYPE                    2

#endif


