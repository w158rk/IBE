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
    std::memcpy(m_signature, signature, SIGN_LEN);
    m_fsignature = true;
}

void SecPacket::unset_signature()
{
    m_fsignature = false;
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

void SecPacket::unset_payload_app()
{
    m_fpayload = false;
}

int SecPacket::get_length()
{
    char *head = get_head();
    return *(int *)(head+4);
}
int SecPacket::get_type()
{
    char *head = get_head();
    return *(int *)(head);
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
    *(int *)(head+4) = length;
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

/**
 * it is the responsibility of the caller to 
 * release the space returned by this function 
 */
SecPacket *SecPacket::from_bytes(char *data)
{

    SecPacket *p_sec_packet = new SecPacket;
    p_sec_packet->set_head(data);
    p_sec_packet->set_payload_byte(data+SEC_HEAD_LEN);
    return p_sec_packet;

}


/**
 * it is the responsibility of the caller to 
 * release the space returned by this function 
 */
char *SecPacket::to_bytes()
{
    int length = get_length();
    char *rtn = (char *)std::malloc(length + SEC_HEAD_LEN);
    std::memcpy(rtn, get_head(), SEC_HEAD_LEN);
    std::memcpy(rtn+APP_HEAD_LEN, get_payload_byte(), length);
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
