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

//该系数是由UAS维护的，UAS在接收到UAC的未鉴权报文后，给UAC回复401，在报文中必须要带相关认证系数和认证方法

//UAS赋值的认证随机数
#define NONCE "9bd055"

//默认加密算法
#define ALGORITHTHM "MD5"

//SIP From的头部
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
	//主机名称
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

//SIP Contract头部
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
	//sip层返回的请求的标志，响应返回即可
	int sipRequestId;

	//维护一次注册
	string callId;
	
	//消息所属的功能方法字符串
	string method;

	//地址编码@域名或IP地址：连接端口，eg：sip:1111@127.0.1:5060
	CSipFromHeader from;
	
	//地址编码@域名或IP地址：链接端口
	CSipFromHeader proxy;

	//地址编码@域名或IP地址：连接端口
	CContractHeader contact;
	
	//消息内容，一般为DDCP消息体XML文档，或者具体协议帧要求其他字符串文本
	string content;

	//响应状态信息
	string status;

	//超时，时间单位为秒
	int expires;
};

struct SipAuthInfo
{
	//平台主机名
	string digestRealm;
	//平台提供随机数
	string nonce;
	//用户名
	string userName;
	//密码
	string response;
	//"SIP:平台地址"，不需要uac赋值
	string uri;
	//加密算法MD5
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
	//获取expires
	osip_header_t*header = NULL;
	{
		osip_message_header_get_byname(request, "expires", 0, &header);
		if (NULL != header && NULL != header->hvalue)
		{
			regInfo.baseInfo.expires = atoi(header->hvalue);
		}
	}
	//contact字段
	osip_contact_t*contact = NULL;
	osip_message_get_contact(request, 0, &contact);
	if (NULL != contact)
	{
		regInfo.baseInfo.contact.SetContractHeader(contact->url->username, contact->url->host, contact->url->port, regInfo.baseInfo.expires);

	}
	//注册返回 由发送方维护的请求ID，接收方接收后原样返回即可
	regInfo.baseInfo.sipRequestId = iReqId;
	//CALL ID
	{
		stream.str("");
		stream << request->call_id->number;
		regInfo.baseInfo.content = stream.str();
	}
	//鉴权信息
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
