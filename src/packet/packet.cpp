#include<packet.hpp>
#include<cstring>

#ifdef DEBUG 
#include<sstream>
#endif

using namespace packet;

GET_AND_SET_IMPL(Packet, interface::IUI *, ui_ptr)
GET_AND_SET_IMPL(Packet, user::User *, user_ptr)
GET_AND_SET_IMPL(Packet, interface::IComm *, comm_ptr)
GET_AND_SET_IMPL(Packet, PacketCTX *, ctx)

GET_AND_SET_IMPL(PacketException, std::string, message)

GET_AND_SET_IMPL(AppPacket, char *, payload)
// GET_AND_SET_IMPL(AppPacket, SignMesg *, sign)

AppPacket::AppPacket()
{
#ifdef DEBUG
    std::ostringstream s;
    s << "create an apppacket at: " << (unsigned long)this;
    interface::IUI::debug(s.str());
#endif
}

AppPacket::~AppPacket()
{
#ifdef DEBUG
    std::ostringstream s;
    s << "delete then apppacket at: " << (unsigned long)this;
    interface::IUI::debug(s.str());
#endif
}

SecPacket::SecPacket()
{
#ifdef DEBUG
    std::ostringstream s;
    s << "create a sec packet at: " << (unsigned long)this;
    interface::IUI::debug(s.str());
#endif
}

SecPacket::~SecPacket()
{
#ifdef DEBUG
    std::ostringstream s;
    s << "delete the sec packet at: " << (unsigned long)this;
    interface::IUI::debug(s.str());
#endif
}

PacketCTX::PacketCTX()
{
#ifdef DEBUG
    std::ostringstream s;
    s << "create a packet ctx at: " << (unsigned long)this;
    interface::IUI::debug(s.str());
#endif
}

PacketCTX::~PacketCTX()
{
#ifdef DEBUG
    std::ostringstream s;
    s << "delete the packet ctx at: " << (unsigned long)this;
    interface::IUI::debug(s.str());
#endif
}


char *AppPacket::get_head() 
{
    if(!m_fhead)
    {
        interface::IUI::error("can not get the head of app packet");
        throw PacketException("can not get the head of app packet");
    }
    return m_head;
}

void AppPacket::set_head(char *head)
{
    std::memcpy(m_head, head, APP_HEAD_LEN);
    m_fhead = true;
}

char *AppPacket::get_id() 
{
    if(!m_fid)
    {
        interface::IUI::error("can not get the head of app packet");
        throw PacketException("can not get the head of app packet");
    }
    return m_id;
}

void AppPacket::set_id(char *id)
{
    std::memcpy(m_id, id, ID_LEN_MAX);
    m_fid = true;
}

void AppPacket::unset_head()
{
    m_fhead = false;
}

int AppPacket::get_length()
{
    char *head = get_head();
    return *(int *)(head+4);
}
int AppPacket::get_type()
{
    char *head = get_head();
    return *(int *)(head);
}
void AppPacket::set_length(int length)
{
    char *head = nullptr;
    if(m_fhead)
    {

        head = m_head;

    } 
    else 
    {

        head = (char *)std::malloc(APP_HEAD_LEN);
        std::memset(head, 0, APP_HEAD_LEN);

    }
    *(int *)(head+4) = length;
    set_head(head);
}
void AppPacket::set_type(int type)
{
    char *head = nullptr;
    if(m_fhead)
    {

        head = m_head;

    } 
    else 
    {

        head = (char *)std::malloc(APP_HEAD_LEN);
        std::memset(head, 0, APP_HEAD_LEN);

    }
    *(int *)(head) = type;
    set_head(head);
}

/**
 * it is the responsibility of the caller to 
 * release the space returned by this function 
 */
AppPacket *AppPacket::from_bytes(char *data)
{

    AppPacket *p_app_packet = new AppPacket;
    p_app_packet->set_head(data);
    p_app_packet->set_payload(data+APP_HEAD_LEN);
    return p_app_packet;

}


/**
 * it is the responsibility of the caller to 
 * release the space returned by this function 
 */
char *AppPacket::to_bytes()
{
    int length = get_length();
    char *rtn = (char *)std::malloc(length + APP_HEAD_LEN);
    std::memcpy(rtn, get_head(), APP_HEAD_LEN);
    std::memcpy(rtn+APP_HEAD_LEN, get_payload(), length);
    return rtn;
}

// ===========================================================================
//                              sec packet
// ===========================================================================

char *SecPacket::get_head() 
{
    if(!m_fhead)
    {
        interface::IUI::error("can not get the head of sec packet");
        throw PacketException("can not get the head of sec packet");
    }
    return m_head;
}

void SecPacket::set_head(char *head)
{
    std::memcpy(m_head, head, SEC_HEAD_LEN);
    m_fhead = true;
}

void SecPacket::unset_head()
{
    m_fhead = false;
}

char *SecPacket::get_signature() 
{
    if(!m_fsignature)
    {
        interface::IUI::error("can not get the signature of sec packet");
        throw PacketException("can not get the signature of sec packet");
    }
    return m_signature;
}

void SecPacket::set_signature(char *signature)
{
    std::memcpy(m_signature, signature, IBE_SIGN_LEN);
    m_fsignature = true;
}

char *SecPacket::get_payload_byte() 
{
    if(!m_fpayload)
    {
        interface::IUI::error("can not get the payload of sec packet");
        throw PacketException("can not get the payload of sec packet");
    }
    return m_payload.data;
}

void SecPacket::set_payload_byte(char *payload)
{
    m_payload.data = payload;
    m_fpayload = true;
}

void SecPacket::unset_payload_byte()
{
    m_fpayload = false;
}

/*====================================================================*/
AppPacket *SecPacket::get_payload_app() 
{
    if(!m_fpayload)
    {
        interface::IUI::error("can not get the payload of sec packet");
        throw PacketException("can not get the payload of sec packet");
    }
    return m_payload.appPacket;
}

void SecPacket::set_payload_app(AppPacket *payload)
{
    m_payload.appPacket = payload;
    m_fpayload = true;
}

/*====================================================================*/

void SecPacket::unset_payload_app()
{
    m_fpayload = false;
}

int SecPacket::get_length()
{
    char *head = get_head();
    return *(int *)(head+TYPE_LEN+ID_LEN_MAX);
}
int SecPacket::get_type()
{
    char *head = get_head();
    return *(int *)(head);
}
char *SecPacket::get_id()
{
    char *head = get_head();
    char *id = (char *)malloc(ID_LEN_MAX);
    memcpy(id, head+TYPE_LEN, ID_LEN_MAX);
}
void SecPacket::set_length(int length)
{
    char *head = nullptr;
    if(m_fhead)
    {

        head = m_head;

    } 
    else 
    {

        head = (char *)std::malloc(APP_HEAD_LEN);
        std::memset(head, 0, APP_HEAD_LEN);

    }
    *(int *)(head+TYPE_LEN+ID_LEN_MAX) = length;
    set_head(head);
}
void SecPacket::set_type(int type)
{
    char *head = nullptr;
    if(m_fhead)
    {

        head = m_head;

    } 
    else 
    {

        head = (char *)std::malloc(APP_HEAD_LEN);
        std::memset(head, 0, APP_HEAD_LEN);

    }
    *(int *)(head) = type;
    set_head(head);
}

void SecPacket::set_id(char *id)
{
    char *head = nullptr;
    if(m_fhead)
    {

        head = m_head;

    } 
    else 
    {

        head = (char *)std::malloc(APP_HEAD_LEN);
        std::memset(head, 0, APP_HEAD_LEN);

    }
    memcpy(head+TYPE_LEN, id, ID_LEN_MAX);
    set_head(head);
}

/**
 * it is the responsibility of the caller to 
 * release the space returned by this function 
 */
SecPacket *SecPacket::from_bytes(char *data)
{

    SecPacket *p_sec_packet = new SecPacket;
    p_sec_packet->set_head(data);
    p_sec_packet->set_signature(data+SEC_HEAD_LEN);
    p_sec_packet->set_payload_byte(data+SEC_HEAD_LEN+IBE_SIGN_LEN);
    return p_sec_packet;

}


/**
 * it is the responsibility of the caller to 
 * release the space returned by this function 
 */
char *SecPacket::to_bytes()
{
    int length = get_length();
    char *rtn = (char *)std::malloc(length + SEC_HEAD_LEN + IBE_SIGN_LEN);
    std::memcpy(rtn, get_head(), SEC_HEAD_LEN);
    std::memcpy(rtn+SEC_HEAD_LEN, get_signature(), IBE_SIGN_LEN);
    std::memcpy(rtn+SEC_HEAD_LEN+IBE_SIGN_LEN, get_payload_byte(), length);
    return rtn;
}


//===================================================================
//          ctx
//===================================================================

GET_AND_SET_IMPL(PacketCTX,  ID *, src_id)
GET_AND_SET_IMPL(PacketCTX,  ID *, dest_id)
GET_AND_SET_IMPL(PacketCTX,  IBEPublicParameters*, mpk)
GET_AND_SET_IMPL(PacketCTX,  IBEPrivateKey*, sk)

GET_AND_SET_IMPL(PacketCTX,  enum state, phase)

AppPacket *PacketCTX::get_payload_app() 
{
    if(!m_fpayload)
    {
        interface::IUI::error("can not get the payload of ctx");
        throw PacketException("can not get the payload of ctx");
    }
    return m_payload.appPacket;
}

void PacketCTX::set_payload_app(AppPacket *payload)
{
    m_payload.appPacket = payload;
    m_fpayload = true;
}

void PacketCTX::unset_payload_app()
{
    m_fpayload = false;
}

SecPacket *PacketCTX::get_payload_sec() 
{
    if(!m_fpayload)
    {
        interface::IUI::error("can not get the payload of ctx");
        throw PacketException("can not get the payload of ctx");
    }
    return m_payload.secPacket;
}

void PacketCTX::set_payload_sec(SecPacket *payload)
{
    m_payload.secPacket = payload;
    m_fpayload = true;
}

void PacketCTX::unset_payload_sec()
{
    m_fpayload = false;
}

int sign_to_bytes(SignMesg *sig, char *buf)
{
    int len = 0;
    while(sig->front!=nullptr)
    {
        int idlen = *(int *)sig->id_len;

        int signlen = *(int *)sig->sign_len;

        memcpy(buf+len,sig->id_len, SIGN_ID_LEN);
        len = len + SIGN_ID_LEN;
        memcpy(buf+len,sig->sign_len, SIGN_LEN);
        len = len + SIGN_LEN;
        memcpy(buf+len,sig->ID, idlen);
        len = len + idlen;
        memcpy(buf+len,sig->PP, IBE_MPK_LEN);
        len = len +IBE_MPK_LEN;
        memcpy(buf+len,sig->sign_data, signlen);
        len = len + signlen;
        sig = sig->front;
    }
    
    int idlen = *(int *)sig->id_len;
    memcpy(buf+len,sig->id_len, SIGN_LEN);
    len = len + SIGN_ID_LEN + SIGN_LEN;
    memcpy(buf+len,sig->ID, idlen);
    len = len + idlen;
    memcpy(buf+len,sig->PP, IBE_MPK_LEN);
    len = len + IBE_MPK_LEN;

    return len;
}

SignMesg *sign_from_bytes(char *sig, int sig_len, int len)
{
    SignMesg *sign = new SignMesg();
    char *id_len = (char *)malloc(SIGN_ID_LEN);
    memcpy(id_len, sig, SIGN_ID_LEN);
    int idlen = *(int *)id_len;
    *(int *)sign->id_len = idlen;
    len = len + SIGN_ID_LEN;
    char *sig_length = (char *)malloc(SIGN_LEN);
    memcpy(sig_length, sig+len, SIGN_LEN);
    int siglen = *(int *)sig_length;
    *(int *)sign->sign_len = siglen;
    len = len + SIGN_LEN;

    char *id = (char *)malloc(idlen);
    memcpy(id, sig+len, idlen);
    sign->ID = id;
    len = len + idlen;

    char *mpk = (char *)malloc(IBE_MPK_LEN);
    memcpy(mpk, sig+len, IBE_MPK_LEN);
    len = len + IBE_MPK_LEN;
    sign->PP = mpk;

    if(len==sig_len)
    {
        sign->sign_data = NULL;
        sign->front = nullptr;
    }
    else
    {
        char *sign_data = (char *)malloc(siglen);
        memcpy(sign_data, sig+len, siglen);
        len = len + siglen;
        sign->sign_data = sign_data;

        sign->front = sign_from_bytes(sig, sig_len, len);

    }
    return sign;
}

int sig_verify(SignMesg *sig, IBEPublicParameters ss_mpk)
{
    int rnt = 0;
    if(sig->front!=nullptr)
    {
        if(!sig_verify(sig->front, ss_mpk))
            goto end;
        int id_len = *(int *)sig->id_len;
        int sig_len = *(int *)sig->sign_len;
        char *data = (char *)malloc(id_len+IBE_MPK_LEN);
        memcpy(data, sig->ID, id_len);
        memcpy(data+id_len, sig->PP, IBE_MPK_LEN);
        
        if(!ibe_verify(data, id_len+IBE_MPK_LEN, sig->sign_data, sig_len, &sig->PP, 239, sig->front->ID, *(int *)sig->front->ID))
        {
            fprintf(stderr, "verify error\n");
            goto end;
        }

    }
    else
    {
        if(strcmp(sig->PP, ss_mpk))
        {
            fprintf(stderr, "error in verify global mpk\n");
            goto end;
        }
    }
    
    rnt = 1;
end:
    return rnt;
}