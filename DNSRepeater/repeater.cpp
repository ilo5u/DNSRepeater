#include "pch.h"
#include "repeater.h"

#define MAX_TRANSFER_TIME 30									//定义转发给本地DNS服务器并得到响应的最大不超时时间

DNSRepeater::DNSRepeater(ipv4_t _local) :
	_success(false),
	_localDnsServer(_local), _pairId(0),
	_resolvers(),
	_messageHander(), _timeHander(),
	_com(_local)
{
}

DNSRepeater::~DNSRepeater()
{
}

void DNSRepeater::Run(int argc)
{
	_success = true;											//控制运行

	//日志
	Log::DebugConfig debugconfig;
	debugconfig.DebugLevel = argc;
	debugconfig.NameSeverIP = _localDnsServer;
	Log LogInfo(debugconfig);

	//加入一个线程,处理转发给DNS服务器超时未响应的情况
	std::thread taskTime(&DNSRepeater::ThreadTimeOut, this);
	taskTime.detach();

	DNSCom::message_t RecvMsg;									//收到的包
	DNSCom::message_t SendMsg;									//待发送的包
	std::pair<ipv4_t, id_t> recvPair;
	std::map<id_t, std::pair<ipv4_t, id_t>>::iterator mapIt;
	std::list<DNSCom::message_t::question_t>::iterator qListIt;
	int blockedFlag = 0;										//为1代表至少有一个question查询的域名被屏蔽，直接回rcode=3
	int notFoundFlag = 0;										//为1代表至少有一个question查询的域名在数据库中查找不到，若blockedFlag==0，直接转发给实际的本地DNS服务器
	int unableFlag = 0;											//为1代表本DNS中继无法处理，eg.被截断的报文, qclass!=1, qtype!=A,mx,cname
	DNSDBMS dbms;

	dbms.Connect();												//连接数据库

	while (_success)
	{
		RecvMsg = _com.RecvFrom();								//接收消息包

		blockedFlag = 0;
		notFoundFlag = 0;
		unableFlag = 0;

		//无法处理被截断的包以及非标准查询	/////（若为本地服务器返回的包，是否还需要存储到数据库？）
		if (RecvMsg.header.flags.tc != 0 || RecvMsg.header.flags.opcode != 0)
		{
			unableFlag = 0;
		}

		//分析收到的包
		switch (RecvMsg.type)
		{
		case DNSCom::message_t::type_t::RECV:					//DNS服务器收到的消息类型都是RECV
			switch (RecvMsg.header.flags.qr)					//判断是查询请求报文（0），或响应报文（1）
			{
			case 0:												//0表示是查询请求报文
				//对每一个question的域名检索DNS数据库，遇到0.0.0.0则推出循环
				for (qListIt = RecvMsg.qs.begin(); qListIt != RecvMsg.qs.end() && blockedFlag == 0 && unableFlag == 0; ++qListIt)
				{
					if (qListIt->cls != DNSCom::message_t::class_t::In ||
						(qListIt->dnstype != DNSCom::message_t::dns_t::A && qListIt->dnstype != DNSCom::message_t::dns_t::MX
							&&qListIt->dnstype != DNSCom::message_t::dns_t::CNAME&&qListIt->dnstype != DNSCom::message_t::dns_t::NS))
					{
						unableFlag = 1;
					}

					DNSDBMS::search_t question
					{
						qListIt->name,
						(int)qListIt->dnstype,
						(int)qListIt->cls
					};

					//查询数据库	
					DNSDBMS::results answers = dbms.Select(question);			

					if (answers.size() > 0)						//在数据库中查询到（普通IP地址 or IP地址为0.0.0.0）
					{
						RecvMsg.header.ancount += (int16_t)answers.size();

						for (DNSDBMS::results::iterator aListIt = answers.begin();
							aListIt != answers.end() && blockedFlag == 0; ++aListIt)
						{
							DNSCom::message_t::answer_t dnsans;
							dnsans.name = aListIt->name;
							dnsans.cls = (DNSCom::message_t::class_t)aListIt->cls;
							dnsans.dnstype = (DNSCom::message_t::dns_t)aListIt->dnstype;
							dnsans.preference = aListIt->preference;
							dnsans.ttl = aListIt->ttl;
							switch (dnsans.dnstype)
							{
							case DNSCom::message_t::dns_t::A:			//A类型
								dnsans.ipv4 = atoi(aListIt->str.c_str());
								break;
							default:
								dnsans.str = aListIt->str;
								break;
							}

							RecvMsg.as.push_back(dnsans);				//插入answer队列

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

				//至少有一个question查询的域名被屏蔽，直接回rcode=3
				if (blockedFlag == 1)							
				{
					SendMsg = RecvMsg;

					SendMsg.header.ancount = 0;
					SendMsg.as.clear();							//清空answer域

					SendMsg.header.flags.rcode = 3;				//表示域名不存在（屏蔽）
					SendMsg.header.flags.qr = 1;				//响应

					SendMsg.ipv4 = RecvMsg.ipv4;				//回应给客户端
				}

				//（至少有一个question查询的域名查不到，且没有域名被屏蔽）或（不能处理），直接转发给实际的本地DNS服务器
				if ((blockedFlag == 0 && notFoundFlag == 1) || unableFlag == 1)		
				{
					SendMsg = RecvMsg;

					SendMsg.header.ancount = 0;
					SendMsg.as.clear();							//清空answer域

					//分配ID，保存到映射表
					id_t pairID = _pairId;
					++_pairId;
					recvPair.first = RecvMsg.ipv4;
					recvPair.second = RecvMsg.header.id;

					_protection.lock();							//与超时处理线程都涉及到解析器的增删，因此需要加锁

					//插入映射表
					_resolvers.insert(std::pair<id_t, std::pair<ipv4_t, id_t>>(pairID, recvPair));
					_messageHander.insert(std::pair<id_t, DNSCom::message_t>(pairID, SendMsg));
					
					SendMsg.header.id = pairID;					//ID转换

					//转发给实际的本地DNS服务器
					SendMsg.ipv4 = _localDnsServer;

					//加入超时处理队列
					time_t currentTime = time(NULL);			//当前时间
					_timeHander.insert(std::pair<id_t, time_t>(pairID, currentTime));

					_protection.unlock();
				}

				//所有question的域名都在数据库查到，且都是普通ip地址
				if (blockedFlag == 0 && notFoundFlag == 0)	
				{
					SendMsg = RecvMsg;

					SendMsg.header.flags.rcode = 0;				//响应报文没有差错
					SendMsg.header.flags.qr = 1;				//响应
				}

				break;
			default:											//!=0表示是来自外部DNS服务器的响应报文
				//转发响应回客户端，通过RecvMsg.header.id来确定响应与查询请求是否匹配	
				mapIt = _resolvers.find(RecvMsg.header.id);

				if (mapIt != _resolvers.end())					//查到
				{
					recvPair = _resolvers[RecvMsg.header.id];	//通过RecvMsg.header.id得到pair

					SendMsg = RecvMsg;
					SendMsg.ipv4 = recvPair.first;				//通过pair的ip地址修改响应消息包的ip
					SendMsg.header.id = recvPair.second;		//id转换
					
					_protection.lock();

					//从解析器中删除
					_resolvers.erase(mapIt);					//已经转发回给客户端，删除映射表该项
					_messageHander.erase(RecvMsg.header.id);
					_timeHander.erase(RecvMsg.header.id);

					_protection.unlock();
				}
				//else											//超时则不处理(超时则在超时处理线程中被删除出解析器，查不到)

				//将查询到的结果插入数据库
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
					case DNSCom::message_t::dns_t::A:			//A类型
						result.str = std::to_string(aListIt->ipv4);
						break;
					default:
						result.str = aListIt->str;
						break;
					}

					//若数据库中已存在则先删除该记录
					dbms.DeleteRecod(result);

					//将查询到的结果插入数据库
					dbms.Insert(result.name, result.ttl, result.cls, result.dnstype, result.preference, result.str);
				}

				break;
			}

			break;

		default:
			break;
		}

		//日志
		/*Log::DebugMsg debugmsg;
		debugmsg.ClientIp = RecvMsg.ipv4;
		//debugmsg.DomainName=
		debugmsg.num = RecvMsg.header.id;
		LogInfo.Write_DebugMsg(debugmsg);*/

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
		_protection.lock();

		//遍历_timeOutIds，若Id仍存在于_timeHander说明该id对应的消息超时
		for (int i = 0; i < _timeOutIds.size(); ++i)
		{
			std::map<id_t, time_t>::iterator timeHanderIt = _timeHander.find(_timeOutIds[i]);
			if (timeHanderIt != _timeHander.end())				//查到，说明未收到包，已超时
			{
				//对超时的包，传回错误信息（rcode设为3）
				DNSCom::message_t SendMsg = _messageHander[_timeOutIds[i]];
				SendMsg.header.flags.qr = 1;					//响应
				SendMsg.header.flags.rcode = 3;					//错误

				_com.SendTo(SendMsg);							//发送错误响应消息回客户端

				//从解析器中删除
				_timeHander.erase(timeHanderIt);				
				_resolvers.erase(_timeOutIds[i]);
				_messageHander.erase(_timeOutIds[i]);
			}
		}
		_timeOutIds.clear();									//清空

		//更新_timeOutIds为当前time最老的id
		//从_timeHander中找到value值（time_t）最小（即最早到的）项
		if (_timeHander.size() != 0)							//不为空
		{
			id_t oldestId = _timeHander.begin()->first;			//加入解析器time最早的id
			for (std::map<id_t, time_t>::iterator timeHanderIt = _timeHander.begin();
				timeHanderIt != _timeHander.end(); ++timeHanderIt)
			{
				if (timeHanderIt->second < _timeHander[oldestId])
				{
					oldestId = timeHanderIt->first;
				}
			}

			//将与最早time同时加入解析器的id加入到当前超时处理vector
			for (std::map<id_t, time_t>::iterator timeHanderIt = _timeHander.begin();
				timeHanderIt != _timeHander.end(); ++timeHanderIt)
			{
				if (timeHanderIt->second == _timeHander[oldestId])
				{
					_timeOutIds.push_back(timeHanderIt->first);
				}
			}

			//计算时间差、TTL
			time_t currentTime = time(NULL);
			int length = (int)difftime(currentTime, _timeHander[oldestId]);
			int TTL = MAX_TRANSFER_TIME - length;

			Sleep(TTL);
		}
		else
		{
			Sleep(MAX_TRANSFER_TIME);
		}

		_protection.unlock();
	}
}
