#pragma once

/// <summary>
/// 32λIPv4��ַ��С�˴洢��
/// </summary>
typedef int32_t ipv4_t;

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
			struct flags_t
			{
				int16_t qr : 1;			// 0����ѯ 1����Ӧ
				int16_t opcode : 4;		// 0����׼��ѯ 1�������ѯ 2��������״̬����
				int16_t aa : 1;			// 0����Ȩ���� 1��Ȩ����
				int16_t tc : 1;			// 0���ǽض� 1���ض�
				int16_t rd : 1;			// 0������ 1���ݹ�
				int16_t ra : 1;			// 0���ݹ鲻���� 1���ݹ����
				int16_t z : 3;			// 0
				int16_t rcode : 4;		// 0��û�в�� 3������������
			};
			flags_t flags;
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
			AAAA = 0x0026
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
			ipv4_t ipv4;		// Aģʽ����Ч
			int16_t preference;
			std::string str;	// CNAME��...ģʽ����Ч
		};

		type_t type;
		ipv4_t ipv4;	// Ŀ�Ļ���Դ��IPv4��ַ������type��������
		DNSCom::dns_t::header_t header;	// ��ͷ
		std::list<question_t> qs;	// �����¼
		std::list<answer_t> as;		// ��Դ��¼
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
	std::mutex _recvlocker;

	/// <summary>
	/// ��������
	/// </summary>
	std::mutex _sendlocker;

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
	std::thread _recvdriver;

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
	SOCKET _recvsock;

	/// <summary>
	/// �󶨵�ǰ������ַ
	/// </summary>
	SOCKADDR_IN _recvaddr;

	/// <summary>
	/// ���׽���
	/// </summary>
	SOCKET _sendsock;

	/// <summary>
	/// ��Ŀ��������ַ
	/// </summary>
	SOCKADDR_IN _sendaddr;

private:
	void _recv();
	void _send();
	
	message_t _analyze(const dns_t& udp, ipv4_t srcipv4);
	dns_t _analyze(const message_t& msg);
};