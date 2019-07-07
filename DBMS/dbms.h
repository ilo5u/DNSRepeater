#pragma once

class DNSDBMS
{
public:
	DNSDBMS();
	~DNSDBMS();

public:
	struct search_t
	{
		std::string name;
		int dnstype;
		int cls;
	};

	struct result_t
	{
		std::string name;
		int dnstype;
		int cls;
		int ttl;
		//std::string ipv4;
		int preference;
		std::string str;
	};

	typedef typename std::list<result_t> results;

public:
	bool Connect();
	void Disconnect();

	//int Select(DNSCom::message_t::question_t question, std::list<DNSCom::message_t::answer_t> &answers);
	DNSDBMS::results Select(DNSDBMS::search_t question);
	void Insert(std::string name, int ttl, int cls, int type, int preference, std::string value);
	void Clear();			//������ݿ�
	int DeleteRecod(result_t answer);			//ɾ����¼

private:
	SQLHENV _env;			//�������
	SQLHDBC _con;			//���Ӿ��
};