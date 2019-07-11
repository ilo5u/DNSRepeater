#include "pch.h"
#include "repeater.h"
#include <iostream>

#define MAX_TRANSFER_TIME 30									//����ת��������DNS���������õ���Ӧ����󲻳�ʱʱ��

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
	_success = true;											//��������

	//��־
	/*Log::DebugConfig debugconfig;
	debugconfig.DebugLevel = argc;
	debugconfig.NameSeverIP = _localDnsServer;
	Log LogInfo(debugconfig);*/

	//����һ���߳�,����ת����DNS��������ʱδ��Ӧ�����
	std::thread taskTime(&DNSRepeater::ThreadTimeOut, this);
	taskTime.detach();

	DNSCom::message_t RecvMsg;									//�յ��İ�
	DNSCom::message_t SendMsg;									//�����͵İ�
	std::pair<ipv4_t, id_t> recvPair;
	std::map<id_t, std::pair<ipv4_t, id_t>>::iterator mapIt;
	std::list<DNSCom::message_t::question_t>::iterator qListIt;
	bool blocked = false;										//Ϊtrue����������һ��question��ѯ�����������Σ�ֱ�ӻ�rcode=3
	bool notFound = false;										//Ϊtrue����������һ��question��ѯ�����������ݿ��в��Ҳ�������blockedFlag==0��ֱ��ת����ʵ�ʵı���DNS������
	bool unable = false;										//Ϊtrue����DNS�м��޷�����eg.���ضϵı���, qclass!=1, qtype!=A,mx,cname
	DNSDBMS dbms;

	dbms.Connect();												//�������ݿ�

	while (_success)
	{
		RecvMsg = _com.RecvFrom();								//������Ϣ��

		blocked = false;
		notFound = false;
		unable = false;

		//�޷������ضϵİ��Լ��Ǳ�׼��ѯ	/////����Ϊ���ط��������صİ����Ƿ���Ҫ�洢�����ݿ⣿��
		if ((RecvMsg.header.flags & 0x0200) != 0 || (RecvMsg.header.flags & 0x7800) != 0)
			unable = true;

		//�����յ��İ�
		switch (RecvMsg.type)
		{
		case DNSCom::message_t::type_t::RECV:					//DNS�������յ�����Ϣ���Ͷ���RECV
		{
			std::cout << "id1: " << RecvMsg.header.id << std::endl;	//////////////////////////////
			std::cout << "q/r = " << (RecvMsg.header.flags & 0x8000) << std::endl;///////////////////
			std::cout << "ip: " << RecvMsg.ipv4 << std::endl;	//////////////////////////////v
			switch (((RecvMsg.header.flags & 0x8000) != 0))		//�ж��ǲ�ѯ�����ģ�0��������Ӧ���ģ�1��
			{
			case 0:												//0��ʾ�ǲ�ѯ������
				//��ÿһ��question����������DNS���ݿ⣬����0.0.0.0���˳�ѭ��
				//for (qListIt = RecvMsg.qs.begin(); qListIt != RecvMsg.qs.end() && blocked == false && unable == false; ++qListIt)
				for (qListIt = RecvMsg.qs.begin(); qListIt != RecvMsg.qs.end() && blocked == false; ++qListIt)	//blocked���ȼ����
				{
					if (qListIt->cls != DNSCom::message_t::class_t::In ||
						(qListIt->dnstype != DNSCom::message_t::dns_t::A && qListIt->dnstype != DNSCom::message_t::dns_t::MX
							&& qListIt->dnstype != DNSCom::message_t::dns_t::CNAME))
					{
						unable = true;
					}

					DNSDBMS::search_t question
					{
						qListIt->name,
						(int)qListIt->dnstype,
						(int)qListIt->cls
					};

					//��ѯ���ݿ�	
					DNSDBMS::results answers = dbms.Select(question);

					if (answers.size() > 0)						//�����ݿ��в�ѯ������ͨIP��ַ or IP��ַΪ0.0.0.0��
					{
						RecvMsg.header.ancount += (int16_t)answers.size();

						for (DNSDBMS::results::iterator aListIt = answers.begin();
							aListIt != answers.end() && blocked == 0; ++aListIt)
						{
							DNSCom::message_t::answer_t dnsans;
							//dnsans.ipv4 = -1;//����ֵ

							dnsans.name = aListIt->name;
							dnsans.cls = (DNSCom::message_t::class_t)aListIt->cls;
							dnsans.dnstype = (DNSCom::message_t::dns_t)aListIt->dnstype;
							dnsans.preference = aListIt->preference;
							dnsans.ttl = aListIt->ttl;
							switch (dnsans.dnstype)
							{
							case DNSCom::message_t::dns_t::A:			//A����
								dnsans.ipv4 = atoi(aListIt->str.c_str());
								break;
							default:
								dnsans.str = aListIt->str;
								break;
							}

							RecvMsg.as.push_back(dnsans);				//����answers����

							if (dnsans.dnstype == DNSCom::message_t::dns_t::A && dnsans.ipv4 == inet_addr("0.0.0.0"))	//IP��ַΪ0.0.0.0
							{
								blocked = true;
							}
						}
					}
					else if (answers.size() == 0)				//δ������������,��ʵ�ʵı���DNS������ת����ѯ����
					{
						notFound = true;
					}
				}

				//������һ��question��ѯ�����������Σ�ֱ�ӻ�rcode=3
				if (blocked)
				{
					SendMsg = RecvMsg;

					SendMsg.header.ancount = 0;
					SendMsg.as.clear();							//���answer��

					SendMsg.header.flags = SendMsg.header.flags & 0xFFF3;				//��ʾ���������ڣ����Σ�
					SendMsg.header.flags = SendMsg.header.flags | 0x0003;
					SendMsg.header.flags = SendMsg.header.flags | 0x8000;				//��Ӧ

					//�Ѿ������汻��ֵ
					//SendMsg.ipv4 = RecvMsg.ipv4;				//��Ӧ���ͻ���
					//SendMsg.port = RecvMsg.port;				
				}
				//��������һ��question��ѯ�������鲻������û�����������Σ��򣨲��ܴ�����ֱ��ת����ʵ�ʵı���DNS������
				//if ((!blocked && notFound) || unable)
				else if (notFound || unable)
				{
					SendMsg = RecvMsg;

					SendMsg.header.ancount = 0;
					SendMsg.as.clear();							//���answer��

					//����ID�����浽ӳ���
					id_t pairID = _pairId;
					++_pairId;
					recvPair.first = RecvMsg.ipv4;
					recvPair.second = RecvMsg.header.id;

					_protection.lock();							//�볬ʱ�����̶߳��漰������������ɾ�������Ҫ����

					//����ӳ���
					_resolvers.insert(std::pair<id_t, std::pair<ipv4_t, id_t>>(pairID, recvPair));
					_messageHander.insert(std::pair<id_t, DNSCom::message_t>(pairID, SendMsg));

					SendMsg.header.id = pairID;					//IDת��

					//ת����ʵ�ʵı���DNS������
					SendMsg.ipv4 = _localDnsServer;
					SendMsg.port = 53;

					//���볬ʱ�������
					_timeHander.insert(std::pair<id_t, time_t>(pairID, std::time(NULL)));

					_protection.unlock();
				}
				//����question�������������ݿ�鵽���Ҷ�����ͨip��ַ
				else if (!blocked && !notFound && !unable)
				{
					SendMsg = RecvMsg;

					SendMsg.header.flags = SendMsg.header.flags & 0xFFF0;				//��Ӧ����û�в��
					SendMsg.header.flags = SendMsg.header.flags | 0x8000;				//��Ӧ
				}

				break;
			default:	//!=0��ʾ�������ⲿDNS����������Ӧ����
				//ת����Ӧ�ؿͻ��ˣ�ͨ��RecvMsg.header.id��ȷ����Ӧ���ѯ�����Ƿ�ƥ��	
				
				_protection.lock();

				mapIt = _resolvers.find(RecvMsg.header.id);

				if (mapIt != _resolvers.end())					//�鵽
				{
					recvPair = _resolvers[RecvMsg.header.id];	//ͨ��RecvMsg.header.id�õ�pair

					SendMsg = RecvMsg;
					SendMsg.ipv4 = recvPair.first;				//ͨ��pair��ip��ַ�޸���Ӧ��Ϣ����ip
					//SendMsg.ipv4 = inet_addr("10.128.223.253");	//////////
					SendMsg.port = _messageHander[RecvMsg.header.id].port;
					SendMsg.header.id = recvPair.second;		//idת��

					//_protection.lock();

					//�ӽ�������ɾ��
					_resolvers.erase(mapIt);					//�Ѿ�ת���ظ��ͻ��ˣ�ɾ��ӳ������
					_messageHander.erase(RecvMsg.header.id);
					_timeHander.erase(RecvMsg.header.id);

					//_protection.unlock();
				}
				//else	//��ʱ�򲻴���(��ʱ���ڳ�ʱ�����߳��б�ɾ�������������鲻��)

				_protection.unlock();

				//����ѯ���Ľ���������ݿ�
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
					case DNSCom::message_t::dns_t::A:			//A����
						result.str = std::to_string(aListIt->ipv4);
						break;
					default:
						result.str = aListIt->str;
						break;
					}

					//�����ݿ����Ѵ�������ɾ���ü�¼
					dbms.DeleteRecod(result);

					//����ѯ���Ľ���������ݿ�
					dbms.Insert(result.name, result.ttl, result.cls, result.dnstype, result.preference, result.str);
				}

				break;
			}

			std::cout << "id2: " << SendMsg.header.id << std::endl <<std::endl;	//////////////////////////////
			//��־
			/*Log::DebugMsg debugmsg;
			debugmsg.ClientIp = ntohl(RecvMsg.ipv4);
			int i = 0;
			for (qListIt = RecvMsg.qs.begin(); qListIt != RecvMsg.qs.end(); ++qListIt, ++i)
			{
				debugmsg.DomainName[i] = qListIt->name;
				//std::cout << qListIt->name << std::endl;			//////////
			}
			debugmsg.DomainName_Num = i;
			debugmsg.id1 = RecvMsg.header.id;
			debugmsg.id2 = SendMsg.header.id;
			LogInfo.Write_DebugMsg(debugmsg);
			LogInfo.Done_DebugMsg();*/

			SendMsg.type = DNSCom::message_t::type_t::SEND;
			_com.SendTo(SendMsg);
		}
			break;

		default:
			break;
		}								//������Ϣ��
	}

	dbms.Disconnect();
}

void DNSRepeater::Stop()
{
	_success = false;
}

void DNSRepeater::ThreadTimeOut()
{
	int TTL = 0;
	while (_success)
	{
		TTL = MAX_TRANSFER_TIME;

		_protection.lock();

		//����_timeOutIds����Id�Դ�����_timeHander˵����id��Ӧ����Ϣ��ʱ
		for (int i = 0; i < (int)_timeOutIds.size(); ++i)
		{
			std::map<id_t, time_t>::iterator timeHanderIt = _timeHander.find(_timeOutIds[i]);
			if (timeHanderIt != _timeHander.end())				//�鵽��˵��δ�յ������ѳ�ʱ
			{
				//�Գ�ʱ�İ������ش�����Ϣ��rcode��Ϊ3��
				DNSCom::message_t SendMsg = _messageHander[_timeOutIds[i]];
				SendMsg.header.flags = SendMsg.header.flags | 0x8000;					//��Ӧ
				SendMsg.header.flags = SendMsg.header.flags & 0xFFF3;					//����
				SendMsg.header.flags = SendMsg.header.flags | 0x0003;
				SendMsg.type = DNSCom::message_t::type_t::SEND;	//��Ϣ����Ϊ����

				_com.SendTo(SendMsg);							//���ʹ�����Ӧ��Ϣ�ؿͻ���

				//�ӽ�������ɾ��
				_timeHander.erase(timeHanderIt);
				_resolvers.erase(_timeOutIds[i]);
				_messageHander.erase(_timeOutIds[i]);
			}
		}
		_timeOutIds.clear();									//���

		//����_timeOutIdsΪ��ǰtime���ϵ�id
		//��_timeHander���ҵ�valueֵ��time_t����С�������絽�ģ���
		if (_timeHander.size() != 0)							//��Ϊ��
		{
			id_t oldestId = _timeHander.begin()->first;			//���������time�����id
			for (std::map<id_t, time_t>::iterator timeHanderIt = _timeHander.begin();
				timeHanderIt != _timeHander.end(); ++timeHanderIt)
			{
				if (timeHanderIt->second < _timeHander[oldestId])
				{
					oldestId = timeHanderIt->first;
				}
			}

			//��������timeͬʱ�����������id���뵽��ǰ��ʱ����vector
			for (std::map<id_t, time_t>::iterator timeHanderIt = _timeHander.begin();
				timeHanderIt != _timeHander.end(); ++timeHanderIt)
			{
				if (timeHanderIt->second == _timeHander[oldestId])
				{
					_timeOutIds.push_back(timeHanderIt->first);
				}
			}

			//����ʱ��TTL
			TTL -= (int)difftime(std::time(NULL), _timeHander[oldestId]);
		}

		_protection.unlock();

		std::this_thread::sleep_for(std::chrono::duration<int>(TTL));
	}
}
