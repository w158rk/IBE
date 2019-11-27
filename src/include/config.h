

#ifndef CONFIG__H
#define CONFIG__H

/* buffer sizes */
#define BUFFER_SIZE             1024
#define SECURITY_BITS           256
#define MAX_ID_LEN              (SECURITY_BITS/8)
#define IBE_BUFFER_SIZE         128


/* server parameters */
#define LISTEN_BACKLOG          50

/*****************************
 * application protocol      *
 *****************************/

#define PLAIN_MESSAGE_TYPE          0
#define PRIVATE_KEY_REQUEST_TYPE    1
#define PRIVATE_KEY_RESPONSE_TYPE   2
#define SESSION_KEY_REQUEST_TYPE    3
#define SESSION_KEY_ACK_TYPE        4
#define SESSION_KEY_FINAL_TYPE      5
#define IBE_MES_TYPE                6

// initialization phase 
# define INIT_MESSAGE_1             7
# define INIT_MESSAGE_2             8
# define INIT_MESSAGE_3             9

/*************************************
 * length 
 *************************************/
#define PRIVATE_KEY_REQUEST_HEAD    5           /* the length of the head */
#define PRIVATE_KEY_RESPONSE_HEAD   1

/** security protocol */
#define NO_ENC_TYPE                 0
#define IBE_TYPE                    1 
#define SM4_TYPE                    2

/* time */
# define INIT_SEND_INTERVAL                  1u

#endif


