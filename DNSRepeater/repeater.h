#pragma once

/// <summary>
/// �ַ������ݵ���󳤶�
/// </summary>
#define STR_MAXN 0x40

/// <summary>
/// �ڴ��л���������Ŀ��Ŀǰ�ݲ�����ʵ�֣�
/// </summary>
#define CACHE_MAXN 0xFF

/// <summary>
/// 32λIPv4��ַ��С�˴洢��
/// </summary>
typedef int32_t ipv4_t;

/// <summary>
/// 16λ�����ʶ
/// </summary>
typedef int16_t id_t;

/// <summary>
/// ҵ���
/// 
/// </summary>
class DNSRepeater
{
public:
	DNSRepeater(ipv4_t _local);
	virtual ~DNSRepeater();

	/// <summary>
	/// ����Ϊ���ú���
	/// </summary>
public:
	DNSRepeater(const DNSRepeater&) = delete;
	DNSRepeater(DNSRepeater&&) = delete;
	DNSRepeater& operator=(const DNSRepeater&) = delete;
	DNSRepeater& operator=(DNSRepeater&&) = delete;

public:
	void Run();
	void Stop();
	void ThreadTimeOut();

public:
	enum class opt_t
	{
		INVALID,
		QUESTION,	// DNS��ѯ
		COMMITED	// �ύ������DNS������
	};

	/// <summary>
	/// ���ݿ����
	/// </summary>
private:
	/// <summary>
	/// ��Դ��¼����
	/// </summary>
	struct recordv4_t
	{
		/// <summary>
		/// 
		/// </summary>
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
			AAAA = 0x0026

		};

		std::string owner;
		int64_t ttl;
		class_t cls;
		type_t type;
		int16_t preference;
		union value_t
		{
			ipv4_t ipv4;
			char str[STR_MAXN];
		};
	};

private:
	/// <summary>
	/// ���п���
	/// </summary>
	bool _success;

private:
	/// <summary>
	/// ʵ�ʵı���DNS������IPv4��ַ
	/// </summary>
	ipv4_t _localDnsServer;

	/// <summary>
	/// �ͻ��˵����ɽ�����
	/// Ψһ��־��һ��IP��UDP��ʶ����Ӧ�Ĳ�������Ŀǰ������״̬�����ڴ����Ѿ��ύ������DNS������...��
	/// �����¼ά����ͨ�ŵ��������У�UDP�����໥��Ӧ��
	/// </summary>
	//std::map<std::pair<ipv4_t, id_t>, opt_t> _resolvers; 
	std::map<id_t, std::pair<ipv4_t, id_t>> _resolvers;		//��pair<ip��id>����һ��pairId����Ϊ�����в�ͬ��ip��ַ�����Ĳ�ѯ����id��ͬ�������Ҫͨ��pairΨһ��ȷ��Դ���յ��ⲿdns���صذ���id��δpairID����
	// std::list<recordv4_t> _cache; // ���棨�ݲ����ǣ�

	/// <summary>
	/// ����ת��������DNS����������ʱδ�õ���Ӧ
	/// </summary>
	typedef std::pair<id_t, time_t> id_ttlPair;				//�洢id�͸���Ϣ��ʼת������ʱ���ĳ�ʼʱ�䣨�ж�ת����ʵ�ʱ��ط������Ƿ�ʱδ��Ӧ��
	struct functor											//��д�º���
	{
		bool operator() (id_ttlPair a, id_ttlPair b)
		{
			return a.second > b.second;						//����ttl��С��������ʱ��С˵���磬���п��ܳ�ʱ��
		}
	};
	std::priority_queue<id_ttlPair, std::vector<id_ttlPair>, functor> _timeoutHander;

private:
	/// <summary>
	/// ͨ�����
	/// </summary>
	DNSCom _com;

private:
	/// <summary>
	/// ������
	/// </summary>
	std::mutex _protection;
};