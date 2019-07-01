#pragma once

/// <summary>
/// 32位IPv4地址（小端存储）
/// </summary>
typedef int32_t ipv4_t;

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
			int16_t qr : 1;			// 0：查询 1：响应
			int16_t opcode : 4;		// 0：标准查询 1：反向查询 2：服务器状态请求
			int16_t aa : 1;			// 0：非权威答案 1：权威答案
			int16_t tc : 1;			// 0：非截断 1：截断
			int16_t rd : 1;			// 0：迭代 1：递归
			int16_t ra : 1;			// 0：递归不可用 1：递归可用
			int16_t z : 3;			// 0
			int16_t rcode : 4;		// 0：没有差错 3：域名不存在
			int16_t qdcount : 16;	// 问题个数
			int16_t ancount : 16;	// 资源个数
			int16_t nscount : 16;	// 忽略
			int16_t arcount : 16;	// 忽略
		};
		header_t header;
		char data[DATA_MAXN];	// 可变长记录
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
			AAAA = 0x0026
		};

		/// <summary>
		/// 
		/// </summary>
		enum class class_t
		{
			In
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
			ipv4_t ipv4;		// A模式下有效
			std::string str;	// CNAME、...模式下有效
		};

		type_t type;
		ipv4_t ipv4;	// 目的或者源的IPv4地址，借助type进行区分
		DNSCom::dns_t::header_t header;	// 包头
		std::list<question_t> qs;	// 问题记录
		std::list<answer_t> as;		// 资源记录
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
	std::mutex _recvlocker;

	/// <summary>
	/// 发互斥锁
	/// </summary>
	std::mutex _sendlocker;

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
	std::thread _recvdriver;

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
	SOCKET _recvsock;

	/// <summary>
	/// 绑定当前主机地址
	/// </summary>
	SOCKADDR_IN _recvaddr;

	/// <summary>
	/// 发套接字
	/// </summary>
	SOCKET _sendsock;

	/// <summary>
	/// 绑定目标主机地址
	/// </summary>
	SOCKADDR_IN _sendaddr;

private:
	void _recv();
	void _send();
	
	message_t _analyze(const dns_t& udp, ipv4_t ipv4);
	dns_t _analyze(const message_t& msg);
};