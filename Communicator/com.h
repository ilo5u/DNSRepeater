#pragma once

/// <summary>
/// 32λIPv4��ַ��С�˴洢��
/// </summary>
typedef int32_t ipv4_t;

typedef int16_t port_t;

/// <summary>
/// 16λ�����ʶ
/// </summary>
typedef int16_t id_t;

/// <summary>
/// ���ڸ���Windows�ں���Դ�����ź�����
/// </summary>
typedef HANDLE handle_t;

/// <summary>
/// DNS���ڳ�ȥ��ͷ��Ŀɱ䳤��Ϣ��֧�ֵ���󳤶�
/// ��ͷ+���ݲ�����512λ
/// </summary>
#define DATA_MAXN ((0x200 - 0xF * 5) + 1)

/// <summary>
/// UDPͨ�����
/// �첽����ҵ������ύ��ͨ������
/// ����Send�Լ�Recv�¼�
/// </summary>
class DNSCom
{
public:
	DNSCom(ipv4_t _local);
	virtual ~DNSCom();

/// <summary>
/// �������º���
/// </summary>
public:
	DNSCom(const DNSCom&) = delete;
	DNSCom(DNSCom&&) = delete;
	DNSCom& operator=(const DNSCom&) = delete;
	DNSCom& operator=(DNSCom&&) = delete;

/// <summary>
/// �ⲿ�ɼ�����
/// </summary>
public:
	/// <summary>
	/// DNS���ĸ�ʽ
	/// </summary>
	struct dns_t
	{
		/// <summary>
		/// ��ͷ
		/// </summary>
		struct header_t
		{
			int16_t id : 16;		// �����ʶ
			int16_t flags;			// ��ʶ
			int16_t qdcount : 16;	// �������
			int16_t ancount : 16;	// ��Դ����
			int16_t nscount : 16;	// ����
			int16_t arcount : 16;	// ����
		};
		header_t header;
		char data[DATA_MAXN];	// �ɱ䳤��¼
		int32_t length;
	};

	/// <summary>
	/// ��ҵ��㽻�������ݰ�����
	/// </summary>
	struct message_t
	{
		/// <summary>
		/// ������
		/// </summary>
		enum class type_t
		{
			INVALID,
			RECV,
			SEND
		};

		/// <summary>
		/// ��ѯ����
		/// </summary>
		enum class dns_t
		{
			A = 0x0001,
			NS = 0x0002,
			CNAME = 0x0005,
			MX = 0x000F,
			AAAA = 0x001C,
			SOA = 0x0006
		};

		/// <summary>
		/// 
		/// </summary>
		enum class class_t
		{
			In = 0x01
		};

		/// <summary>
		/// ��������
		/// </summary>
		struct question_t
		{
			std::string name;
			dns_t dnstype;
			class_t cls;
		};

		/// <summary>
		/// ��Դ��¼����
		/// </summary>
		struct answer_t
		{
			std::string name;
			dns_t dnstype;
			class_t cls;
			int32_t ttl;
			int16_t datalength;
			ipv4_t ipv4;		// Aģʽ����Ч
			int16_t preference;
			std::string str;	// CNAME��...ģʽ����Ч
		};

		struct nameserver_t
		{
			std::string name;
			dns_t dnstype;
			class_t cls;
			int32_t ttl;
			int16_t datalength;
			std::string primary;
			std::string mailbox;
			int32_t number;
			int32_t refresh;
			int32_t retry;
			int32_t limit;
			int32_t minttl;
		};

		type_t type;
		ipv4_t ipv4;
		port_t port;
		DNSCom::dns_t::header_t header;	// ��ͷ
		std::list<question_t> qs;		// �����¼
		std::list<answer_t> as;			// ��Դ��¼
		std::list<nameserver_t> ns;		// ���ַ�������¼
	};

public:
	message_t RecvFrom();
	void SendTo(const message_t& msg);

private:
	/// <summary>
	/// ���п���
	/// </summary>
	bool _success;

	/// <summary>
	/// ����DNS��������IPv4��ַ
	/// </summary>
	ipv4_t _localDnsServer;

/// <summary>
/// ͨ�ſ���
/// </summary>
private:
	/// <summary>
	/// �ջ�����
	/// </summary>
	std::mutex _clientlocker;

	/// <summary>
	/// ��������
	/// </summary>
	std::mutex _locallocker;

	/// <summary>
	/// ���ź���
	/// </summary>
	handle_t _recvcounter;

	/// <summary>
	/// ���ź���
	/// </summary>
	handle_t _sendcounter;

	/// <summary>
	/// ���հ�����
	/// </summary>
	std::queue<message_t> _udprecvs;

	/// <summary>
	/// ����������
	/// </summary>
	std::queue<message_t> _udpsends;

	/// <summary>
	/// ���߳̿���
	/// </summary>
	std::thread _recvclientdriver;

	/// <summary>
/// ���߳̿���
/// </summary>
	std::thread _recvlocaldriver;

	/// <summary>
	/// ���߳̿���
	/// </summary>
	std::thread _senddriver;

/// <summary>
/// ͨ�Ž���
/// </summary>
private:
	/// <summary>
	/// ���׽���
	/// </summary>
	SOCKET _clientsock;

	/// <summary>
	/// �󶨵�ǰ������ַ
	/// </summary>
	SOCKADDR_IN _toclientaddr;

	/// <summary>
	/// ���׽���
	/// </summary>
	SOCKET _localsock;

	/// <summary>
	/// ��Ŀ��������ַ
	/// </summary>
	SOCKADDR_IN _tolocaladdr;

private:
	void _recvclient();
	void _recvlocal();
	void _send();
	
	message_t _analyze(const dns_t& udp, ipv4_t srcipv4, port_t srcport);
	dns_t _analyze(const message_t& msg);
};