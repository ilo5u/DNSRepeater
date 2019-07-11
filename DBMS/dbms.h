#pragma once

/// <summary>
/// 数据库中存储dnsname的最大长度
/// </summary>
#define NAME_LEN 260

/// <summary>
/// 数据库中存储dnsvalue的最大长度
/// </summary>
#define VALUE_LEN 100

class DNSDBMS
{
public:
	DNSDBMS();
	~DNSDBMS();

public:
	enum class class_t
	{
		In = 1
	};

	enum class type_t
	{
		A = 0x0001,
		NS = 0x0002,
		CNAME = 0x0005,
		SOA = 0x0006,
		MB = 0x0007,
		MG = 0x0008,
		MR = 0x0009,
		NUL = 0x000A,
		WKS = 0x000B,
		PTR = 0x000C,
		HINF = 0x000D,
		MINFO = 0x000E,
		MX = 0x000F,
		TXT = 0x0010,
		AAAA = 0x001C

	};

	struct search_t
	{
		std::string name;
		int dnstype{ (int)type_t::A };
		int cls{ (int)class_t::In };
	};

	struct result_t
	{
		std::string name;
		int dnstype{ (int)type_t::A };
		int cls{ (int)class_t::In };
		int ttl{ 0 };
		//std::string ipv4;
		int preference{ 0 };
		std::string str;
	};

	typedef typename std::list<result_t> results;

public:
	bool Connect();
	void Disconnect();

	//int Select(DNSCom::message_t::question_t question, std::list<DNSCom::message_t::answer_t> &answers);
	DNSDBMS::results Select(DNSDBMS::search_t question);
	void Insert(std::string name, int ttl, int cls, int type, int preference, std::string value);
	void Clear();			//清空数据库
	int DeleteRecod(result_t answer);			//删除记录

private:
	SQLHENV _env;			//环境句柄
	SQLHDBC _con;			//连接句柄
};