#pragma once

/// <summary>
/// 32位IPv4地址（小端存储）
/// </summary>
typedef int32_t ipv4_t;

typedef int16_t port_t;

/// <summary>
/// 16位事务标识
/// </summary>
typedef int16_t id_t;

/// <summary>
/// 用于各类Windows内核资源（如信号量）
/// </summary>
typedef HANDLE handle_t;

/// <summary>
/// DNS包内除去包头后的可变长信息所支持的最大长度
/// 包头+数据不超过512位
/// </summary>
#define DATA_MAXN ((0x200 - 0xF * 5) + 1)

/// <summary>
/// UDP通信组件
/// 异步处理业务层所提交的通信事务
/// 包含Send以及Recv事件
/// </summary>
class DNSCom
{
public:
	DNSCom(ipv4_t _local);
	virtual ~DNSCom();

/// <summary>
/// 弃用以下函数
/// </summary>
public:
	DNSCom(const DNSCom&) = delete;
	DNSCom(DNSCom&&) = delete;
	DNSCom& operator=(const DNSCom&) = delete;
	DNSCom& operator=(DNSCom&&) = delete;

/// <summary>
/// 外部可见类型
/// </summary>
public:
	/// <summary>
	/// DNS报文格式
	/// </summary>
	struct dns_t
	{
		/// <summary>
		/// 包头
		/// </summary>
		struct header_t
		{
			int16_t id : 16;		// 事务标识
			int16_t flags;			// 标识
			int16_t qdcount : 16;	// 问题个数
			int16_t ancount : 16;	// 资源个数
			int16_t nscount : 16;	// 忽略
			int16_t arcount : 16;	// 忽略
		};
		header_t header;
		char data[DATA_MAXN];	// 可变长记录
		int32_t length;
	};

	/// <summary>
	/// 与业务层交换的数据包类型
	/// </summary>
	struct message_t
	{
		/// <summary>
		/// 包类型
		/// </summary>
		enum class type_t
		{
			INVALID,
			RECV,
			SEND
		};

		/// <summary>
		/// 查询类型
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
		/// 问题类型
		/// </summary>
		struct question_t
		{
			std::string name;
			dns_t dnstype;
			class_t cls;
		};

		/// <summary>
		/// 资源记录类型
		/// </summary>
		struct answer_t
		{
			std::string name;
			dns_t dnstype;
			class_t cls;
			int32_t ttl;
			int16_t datalength;
			ipv4_t ipv4;		// A模式下有效
			int16_t preference;
			std::string str;	// CNAME、...模式下有效
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
		DNSCom::dns_t::header_t header;	// 包头
		std::list<question_t> qs;		// 问题记录
		std::list<answer_t> as;			// 资源记录
		std::list<nameserver_t> ns;		// 名字服务器记录
	};

public:
	message_t RecvFrom();
	void SendTo(const message_t& msg);

private:
	/// <summary>
	/// 运行控制
	/// </summary>
	bool _success;

	/// <summary>
	/// 本地DNS服务器的IPv4地址
	/// </summary>
	ipv4_t _localDnsServer;

/// <summary>
/// 通信控制
/// </summary>
private:
	/// <summary>
	/// 收互斥锁
	/// </summary>
	std::mutex _clientlocker;

	/// <summary>
	/// 发互斥锁
	/// </summary>
	std::mutex _locallocker;

	/// <summary>
	/// 收信号量
	/// </summary>
	handle_t _recvcounter;

	/// <summary>
	/// 发信号量
	/// </summary>
	handle_t _sendcounter;

	/// <summary>
	/// 已收包队列
	/// </summary>
	std::queue<message_t> _udprecvs;

	/// <summary>
	/// 待发包队列
	/// </summary>
	std::queue<message_t> _udpsends;

	/// <summary>
	/// 收线程控制
	/// </summary>
	std::thread _recvclientdriver;

	/// <summary>
/// 收线程控制
/// </summary>
	std::thread _recvlocaldriver;

	/// <summary>
	/// 发线程控制
	/// </summary>
	std::thread _senddriver;

/// <summary>
/// 通信介质
/// </summary>
private:
	/// <summary>
	/// 收套接字
	/// </summary>
	SOCKET _clientsock;

	/// <summary>
	/// 绑定当前主机地址
	/// </summary>
	SOCKADDR_IN _toclientaddr;

	/// <summary>
	/// 发套接字
	/// </summary>
	SOCKET _localsock;

	/// <summary>
	/// 绑定目标主机地址
	/// </summary>
	SOCKADDR_IN _tolocaladdr;

private:
	void _recvclient();
	void _recvlocal();
	void _send();
	
	message_t _analyze(const dns_t& udp, ipv4_t srcipv4, port_t srcport);
	dns_t _analyze(const message_t& msg);
};