#include<iostream>
#include<string>
#include<sstream>
#include<stdlib.h>

#include<osip_message.h>
#include<osip_parser.h>
#include<osip_port.h>

#include<eXosip.h>
#include<eX_setup.h>
#include<eX_register.h>
#include<eX_options.h>
#include<eX_message.h>
#include<winsock.h>
#include<WinSock2.h>
#include<sys/types.h>

using namespace std;
#define LISTEN_ADDR ("192.168.50.57")

#define UASPORT (5060)

//��ϵ������UASά���ģ�UAS�ڽ��յ�UAC��δ��Ȩ���ĺ󣬸�UAC�ظ�401���ڱ����б���Ҫ�������֤ϵ������֤����

//UAS��ֵ����֤�����
#define NONCE "9bd055"

//Ĭ�ϼ����㷨
#define ALGORITHTHM "MD5"

//SIP From��ͷ��
class CSipFromHeader
{
public:
	CSipFromHeader()
	{

	}
	CSipFromHeader()
	{

	}
	void SetHeader(string addrCod, string addrI, string addrPor)
	{
		addrCode = addrCod;
		addrIp = addrI;
		addrPort = addrPor;
	}
	string GetFromatHeader()
	{
		std::stringstream stream;
		stream << "<sip:" << addrCode << "@" << addrIp << ":" << addrPort << ">";
		return stream.str();
	}
	//��������
	string GetRealName()
	{
		std::stringstream stream;
		stream << addrIp;
		return stream.str();
	}

private:
	string addrCode;
	string addrIp;
	string addrPort;
};

//SIP Contractͷ��
class CContractHeader :public CSipFromHeader
{
public:
	CContractHeader()
	{

	}
	~CContractHeader()
	{

	}
	void SetContractHeader(string addrCod, string addrI, string addrPor,int expire)
	{
		SetHeader(addrCod, addrI, addrPor);
		expires = expire;
	}
	string GetContractFormatHeader(bool bExpires)
	{
		if (!bExpires)
		{
			return GetFromatHeader();
		}
		else
		{
			string sTmp = GetFromatHeader();
			std::stringstream stream;
			stream << ";" << "expires=" << expires;
			sTmp += stream.str();
			return sTmp;
		}
	}
private:
	int expires;
};
struct SipContextInfo
{
	//sip�㷵�ص�����ı�־����Ӧ���ؼ���
	int sipRequestId;

	//ά��һ��ע��
	string callId;
	
	//��Ϣ�����Ĺ��ܷ����ַ���
	string method;

	//��ַ����@������IP��ַ�����Ӷ˿ڣ�eg��sip:1111@127.0.1:5060
	CSipFromHeader from;
	
	//��ַ����@������IP��ַ�����Ӷ˿�
	CSipFromHeader proxy;

	//��ַ����@������IP��ַ�����Ӷ˿�
	CContractHeader contact;
	
	//��Ϣ���ݣ�һ��ΪDDCP��Ϣ��XML�ĵ������߾���Э��֡Ҫ�������ַ����ı�
	string content;

	//��Ӧ״̬��Ϣ
	string status;

	//��ʱ��ʱ�䵥λΪ��
	int expires;
};

struct SipAuthInfo
{
	//ƽ̨������
	string digestRealm;
	//ƽ̨�ṩ�����
	string nonce;
	//�û���
	string userName;
	//����
	string response;
	//"SIP:ƽ̨��ַ"������Ҫuac��ֵ
	string uri;
	//�����㷨MD5
	string algorithm;
};
struct sipRegisterInfo
{
	SipContextInfo baseInfo;
	SipAuthInfo authInfo;
	bool isAuthNull;
};

void parserRegisterInfo(osip_message_t*request, int iReqId, sipRegisterInfo&regInfo)
{
	std::stringstream stream;
	regInfo.baseInfo.method = request->sip_method;
	regInfo.baseInfo.from.SetHeader(request->from->url->username, request->from->url->host, request->from->url->port);
	regInfo.baseInfo.proxy.SetHeader(request->to->url->username, request->to->url->host, request->to->url->port);
	//��ȡexpires
	osip_header_t*header = NULL;
	{
		osip_message_header_get_byname(request, "expires", 0, &header);
		if (NULL != header && NULL != header->hvalue)
		{
			regInfo.baseInfo.expires = atoi(header->hvalue);
		}
	}
	//contact�ֶ�
	osip_contact_t*contact = NULL;
	osip_message_get_contact(request, 0, &contact);
	if (NULL != contact)
	{
		regInfo.baseInfo.contact.SetContractHeader(contact->url->username, contact->url->host, contact->url->port, regInfo.baseInfo.expires);

	}
	//ע�᷵�� �ɷ��ͷ�ά��������ID�����շ����պ�ԭ�����ؼ���
	regInfo.baseInfo.sipRequestId = iReqId;
	//CALL ID
	{
		stream.str("");
		stream << request->call_id->number;
		regInfo.baseInfo.content = stream.str();
	}
	//��Ȩ��Ϣ
	osip_authorization_t*authentication = NULL;
	{
		osip_message_get_authorization(request, 0, &authentication);
		if (NULL == authentication)
		{
			regInfo.isAuthNull = true;
		}
		else
		{
			regInfo.isAuthNull = false;
			stream.str("");
			stream << authentication->username;
			regInfo.authInfo.userName = stream.str();
			stream.str("");

		}
	}
}
