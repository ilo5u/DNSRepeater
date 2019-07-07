#include "pch.h"
#include "repeater.h"

#define MAX_TRANSFER_TIME 30									//定义转发给本地DNS服务器并得到响应的最大不超时时间

DNSRepeater::DNSRepeater(ipv4_t _local) :
	_success(false),
	_localDnsServer(_local),
	_resolvers(),
	_com(_local)
{
}

DNSRepeater::~DNSRepeater()
{
}

void DNSRepeater::Run()
{
	//假如一个线程处理转发给DNS服务器超时未响应的情况
	std::thread taskTime(&DNSRepeater::ThreadTimeOut, this);
	taskTime.detach();

	DNSCom::message_t RecvMsg;
	DNSCom::message_t SendMsg;
	std::pair<ipv4_t, id_t> recvPair;
	std::map<id_t, std::pair<ipv4_t, id_t>>::iterator mapIt;
	std::list<DNSCom::message_t::question_t>::iterator qListIt;
	int blockedFlag = 0;										//为1代表至少有一个question查询的域名被屏蔽，直接回rcode=3
	int notFoundFlag = 0;										//为1代表至少有一个question查询的域名再数据库中查找不到，直接转发给实际的本地DNS服务器
	DNSDBMS dbms;

	dbms.Connect();

	while (_success)
	{
		RecvMsg = _com.RecvFrom();								//接收消息包

		switch (RecvMsg.type)
		{
		case DNSCom::message_t::type_t::RECV:					//DNS服务器收到的消息类型都是RECV
			switch (RecvMsg.header.qr)							//判断是查询请求报文（0），或响应报文（1）
			{
			case 0:												//0表示是查询请求报文
				blockedFlag = 0;
				notFoundFlag = 0;

				//对每一个question的域名检索DNS数据库
				for (qListIt = RecvMsg.qs.begin(); qListIt != RecvMsg.qs.end() && blockedFlag == 0; ++qListIt)
				{
					DNSDBMS::search_t question
					{
						qListIt->name,
						(int)qListIt->dnstype,
						(int)qListIt->cls
					};
					//DNSCom::message_t::question_t question = *qListIt;
					DNSDBMS::results answers = dbms.Select(question);			//查询数据库				
					DNSCom::message_t::answer_t dnsans;
					if (answers.size() > 0)						//普通IP地址 or IP地址为0.0.0.0
					{
						RecvMsg.header.ancount += (int16_t)answers.size();
						for (DNSDBMS::results::iterator aListIt = answers.begin();
							aListIt != answers.end() && blockedFlag == 0; ++aListIt)
						{
							dnsans.name = aListIt->name;
							dnsans.cls = (DNSCom::message_t::class_t)aListIt->cls;
							dnsans.dnstype = (DNSCom::message_t::dns_t)aListIt->dnstype;
							dnsans.preference = aListIt->preference;
							dnsans.ttl = aListIt->ttl;
							switch (dnsans.dnstype)
							{
							case DNSCom::message_t::dns_t::A:
								dnsans.ipv4 = atoi(aListIt->str.c_str());
								break;
							default:
								dnsans.str = aListIt->str;
								break;
							}

							RecvMsg.as.push_back(dnsans);

							if (dnsans.ipv4 == inet_addr("0.0.0.0"))	//IP地址为0.0.0.0
							{
								blockedFlag = 1;
							}
						}
					}
					else if (answers.size() == 0)				//未检索到该域名,向实际的本地DNS服务器转发查询请求
					{
						notFoundFlag = 1;
					}
				}

				if (blockedFlag == 1)							//至少有一个question查询的域名被屏蔽，直接回rcode=3
				{
					SendMsg = RecvMsg;

					SendMsg.header.ancount = 0;
					SendMsg.as.clear();							//清空answer域

					SendMsg.header.rcode = 3;					//表示域名不存在（屏蔽）
					SendMsg.header.qr = 1;						//响应

					SendMsg.ipv4 = RecvMsg.ipv4;				//回应给客户端
				}
				else if (notFoundFlag == 1)						//至少有一个question查询的域名查不到，且没有域名被屏蔽，直接转发给实际的本地DNS服务器
				{
					SendMsg = RecvMsg;

					SendMsg.header.ancount = 0;
					SendMsg.as.clear();							//清空answer域

					//分配ID，保存到映射表
					id_t pairID = (int16_t)_resolvers.size();
					recvPair.first = RecvMsg.ipv4;
					recvPair.second = RecvMsg.header.id;
					_resolvers.insert(std::pair<id_t, std::pair<ipv4_t, id_t>>(pairID, recvPair));
					SendMsg.header.id = pairID;					//ID转换

					//转发给实际的本地DNS服务器
					SendMsg.ipv4 = _localDnsServer;

					//加入超时处理队列
					_protection.lock();

					time_t currentTime = time(NULL);
					_timeoutHander.push(id_ttlPair(pairID, currentTime));

					_protection.unlock();
				}
				else if (blockedFlag == 0 && notFoundFlag == 0)	//所有question的域名查数据库都是普通ip地址
				{
					SendMsg = RecvMsg;

					SendMsg.header.rcode = 0;					//响应报文没有差错
					SendMsg.header.qr = 1;						//响应
				}
				break;
			case 1:												//1表示是来自外部DNS服务器的响应报文
				//转发响应回客户端，通过RecvMsg.header.id来确定响应与查询请求是否匹配	
				mapIt = _resolvers.find(RecvMsg.header.id);

				if (mapIt != _resolvers.end())					//查到
				{
					recvPair = _resolvers[RecvMsg.header.id];	//通过RecvMsg.header.id得到pair
					SendMsg = RecvMsg;
					SendMsg.ipv4 = recvPair.first;				//通过pair的地址修改转发消息包的ip
					_resolvers.erase(mapIt);					//已经转发回给客户端，删除映射表该项
				}
				//else											//超时处理(超时则已被删除，查不到)

				//对查询到的结果插入数据库
				for (std::list<DNSCom::message_t::answer_t>::iterator aListIt = RecvMsg.as.begin();
					aListIt != RecvMsg.as.end(); ++aListIt)
				{
					DNSDBMS::result_t result;
					result.name = aListIt->name;
					result.cls = (int)aListIt->cls;
					result.dnstype = (int)aListIt->dnstype;
					result.preference = (int)aListIt->preference;
					result.ttl = (int)aListIt->ttl;
					switch (aListIt->dnstype)
					{
					case DNSCom::message_t::dns_t::A:
						result.str = std::to_string(aListIt->ipv4);
						break;
					default:
						result.str = aListIt->str;
						break;
					}
					//若数据库中已存在则先删除该记录
					dbms.DeleteRecod(result);

					//将查询到的结果插入数据库
					dbms.Insert(aListIt->name, aListIt->ttl, (int)aListIt->cls, (int)aListIt->dnstype, aListIt->preference, aListIt->str);
				}
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
		_com.SendTo(SendMsg);									//发送消息包
	}

	dbms.Disconnect();
}

void DNSRepeater::Stop()
{
	_success = false;
}

void DNSRepeater::ThreadTimeOut()
{
	while (_success)
	{
		//只对优先队列的头部（并且已超时）处理
		time_t currentTime = time(NULL);
		if (!_timeoutHander.empty())
		{
			int length = (int)difftime(currentTime, _timeoutHander.top().second);
			if (length >= MAX_TRANSFER_TIME)					//超时
			{
				_protection.lock();

				//对超时的处理，重传or传回错误信息？
				DNSCom::message_t SendMsg;
				////////
				_com.SendTo(SendMsg);

				_resolvers.erase(_timeoutHander.top().first);	//从id映射表中删除

				_timeoutHander.pop();							//从超时处理队列弹出

				_protection.unlock();
			}
		}
	}
}
