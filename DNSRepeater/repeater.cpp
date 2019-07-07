#include "pch.h"
#include "repeater.h"

#define MAX_TRANSFER_TIME 30									//����ת��������DNS���������õ���Ӧ����󲻳�ʱʱ��

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
	//����һ���̴߳���ת����DNS��������ʱδ��Ӧ�����
	std::thread taskTime(&DNSRepeater::ThreadTimeOut, this);
	taskTime.detach();

	DNSCom::message_t RecvMsg;
	DNSCom::message_t SendMsg;
	std::pair<ipv4_t, id_t> recvPair;
	std::map<id_t, std::pair<ipv4_t, id_t>>::iterator mapIt;
	std::list<DNSCom::message_t::question_t>::iterator qListIt;
	int blockedFlag = 0;										//Ϊ1����������һ��question��ѯ�����������Σ�ֱ�ӻ�rcode=3
	int notFoundFlag = 0;										//Ϊ1����������һ��question��ѯ�����������ݿ��в��Ҳ�����ֱ��ת����ʵ�ʵı���DNS������
	DNSDBMS dbms;

	dbms.Connect();

	while (_success)
	{
		RecvMsg = _com.RecvFrom();								//������Ϣ��

		switch (RecvMsg.type)
		{
		case DNSCom::message_t::type_t::RECV:					//DNS�������յ�����Ϣ���Ͷ���RECV
			switch (RecvMsg.header.qr)							//�ж��ǲ�ѯ�����ģ�0��������Ӧ���ģ�1��
			{
			case 0:												//0��ʾ�ǲ�ѯ������
				blockedFlag = 0;
				notFoundFlag = 0;

				//��ÿһ��question����������DNS���ݿ�
				for (qListIt = RecvMsg.qs.begin(); qListIt != RecvMsg.qs.end() && blockedFlag == 0; ++qListIt)
				{
					DNSDBMS::search_t question
					{
						qListIt->name,
						(int)qListIt->dnstype,
						(int)qListIt->cls
					};
					//DNSCom::message_t::question_t question = *qListIt;
					DNSDBMS::results answers = dbms.Select(question);			//��ѯ���ݿ�				
					DNSCom::message_t::answer_t dnsans;
					if (answers.size() > 0)						//��ͨIP��ַ or IP��ַΪ0.0.0.0
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

							if (dnsans.ipv4 == inet_addr("0.0.0.0"))	//IP��ַΪ0.0.0.0
							{
								blockedFlag = 1;
							}
						}
					}
					else if (answers.size() == 0)				//δ������������,��ʵ�ʵı���DNS������ת����ѯ����
					{
						notFoundFlag = 1;
					}
				}

				if (blockedFlag == 1)							//������һ��question��ѯ�����������Σ�ֱ�ӻ�rcode=3
				{
					SendMsg = RecvMsg;

					SendMsg.header.ancount = 0;
					SendMsg.as.clear();							//���answer��

					SendMsg.header.rcode = 3;					//��ʾ���������ڣ����Σ�
					SendMsg.header.qr = 1;						//��Ӧ

					SendMsg.ipv4 = RecvMsg.ipv4;				//��Ӧ���ͻ���
				}
				else if (notFoundFlag == 1)						//������һ��question��ѯ�������鲻������û�����������Σ�ֱ��ת����ʵ�ʵı���DNS������
				{
					SendMsg = RecvMsg;

					SendMsg.header.ancount = 0;
					SendMsg.as.clear();							//���answer��

					//����ID�����浽ӳ���
					id_t pairID = (int16_t)_resolvers.size();
					recvPair.first = RecvMsg.ipv4;
					recvPair.second = RecvMsg.header.id;
					_resolvers.insert(std::pair<id_t, std::pair<ipv4_t, id_t>>(pairID, recvPair));
					SendMsg.header.id = pairID;					//IDת��

					//ת����ʵ�ʵı���DNS������
					SendMsg.ipv4 = _localDnsServer;

					//���볬ʱ�������
					_protection.lock();

					time_t currentTime = time(NULL);
					_timeoutHander.push(id_ttlPair(pairID, currentTime));

					_protection.unlock();
				}
				else if (blockedFlag == 0 && notFoundFlag == 0)	//����question�����������ݿⶼ����ͨip��ַ
				{
					SendMsg = RecvMsg;

					SendMsg.header.rcode = 0;					//��Ӧ����û�в��
					SendMsg.header.qr = 1;						//��Ӧ
				}
				break;
			case 1:												//1��ʾ�������ⲿDNS����������Ӧ����
				//ת����Ӧ�ؿͻ��ˣ�ͨ��RecvMsg.header.id��ȷ����Ӧ���ѯ�����Ƿ�ƥ��	
				mapIt = _resolvers.find(RecvMsg.header.id);

				if (mapIt != _resolvers.end())					//�鵽
				{
					recvPair = _resolvers[RecvMsg.header.id];	//ͨ��RecvMsg.header.id�õ�pair
					SendMsg = RecvMsg;
					SendMsg.ipv4 = recvPair.first;				//ͨ��pair�ĵ�ַ�޸�ת����Ϣ����ip
					_resolvers.erase(mapIt);					//�Ѿ�ת���ظ��ͻ��ˣ�ɾ��ӳ������
				}
				//else											//��ʱ����(��ʱ���ѱ�ɾ�����鲻��)

				//�Բ�ѯ���Ľ���������ݿ�
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
					//�����ݿ����Ѵ�������ɾ���ü�¼
					dbms.DeleteRecod(result);

					//����ѯ���Ľ���������ݿ�
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
		_com.SendTo(SendMsg);									//������Ϣ��
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
		//ֻ�����ȶ��е�ͷ���������ѳ�ʱ������
		time_t currentTime = time(NULL);
		if (!_timeoutHander.empty())
		{
			int length = (int)difftime(currentTime, _timeoutHander.top().second);
			if (length >= MAX_TRANSFER_TIME)					//��ʱ
			{
				_protection.lock();

				//�Գ�ʱ�Ĵ����ش�or���ش�����Ϣ��
				DNSCom::message_t SendMsg;
				////////
				_com.SendTo(SendMsg);

				_resolvers.erase(_timeoutHander.top().first);	//��idӳ�����ɾ��

				_timeoutHander.pop();							//�ӳ�ʱ������е���

				_protection.unlock();
			}
		}
	}
}
