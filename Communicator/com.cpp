#include "stdafx.h"
#include "com.h"

/// <summary>
/// 默认使用的中继DNS服务器的IPv4地址
/// </summary>
#define HOST_IPADDR "127.0.0.1"

/// <summary>
/// DNS端口号
/// </summary>
#define DNS_PORT 53

/// <summary>
/// 通信环境配置
/// </summary>
/// <param name="_local">本地DNS服务器的IPv4地址</param>
DNSCom::DNSCom(ipv4_t _local) :
	_success(false),
	_localDnsServer(_local),
	_recvlocker(), _sendlocker(),
	_recvcounter(nullptr), _sendcounter(nullptr),
	_udprecvs(), _udpsends(),
	_recvdriver(), _senddriver(),
	_recvsock(0x00), _recvaddr(),
	_sendsock(0x00), _sendaddr()
{
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;
	int ret = WSAStartup(wVersionRequested, &wsaData);
	if (ret == 0)
	{
		if (LOBYTE(wsaData.wVersion) == 2
			&& HIBYTE(wsaData.wVersion) == 2)
		{
			/* 套接字初始化 */
			_recvsock = socket(AF_INET, SOCK_DGRAM, 0);
			_sendsock = socket(AF_INET, SOCK_DGRAM, 0);
			if (_recvsock != INVALID_SOCKET
				&& _sendsock != INVALID_SOCKET)
			{
				std::memset(&_recvaddr, 0, sizeof(_recvaddr));
				_recvaddr.sin_addr.S_un.S_addr = htonl(inet_addr(HOST_IPADDR));
				_recvaddr.sin_family = AF_INET;
				_recvaddr.sin_port = htons(DNS_PORT);

				ret = bind(_recvsock, (LPSOCKADDR)&_recvaddr, sizeof(SOCKADDR));
				if (ret == 0)
				{
					/* 通信控制组件初始化 */
					_recvcounter = CreateSemaphore(NULL, 0x00, 0xFF, NULL);
					_sendcounter = CreateSemaphore(NULL, 0x00, 0xFF, NULL);

					_recvdriver = std::move(std::thread{ std::bind(&DNSCom::_recv, this) });
					_senddriver = std::move(std::thread{ std::bind(&DNSCom::_send, this) });

					_success = true;
				}
				else
				{
					closesocket(_sendsock);
					closesocket(_recvsock);
					WSACleanup();
				}
			}
			else
			{
				closesocket(_sendsock);
				closesocket(_recvsock);
				WSACleanup();
			}
		}
		else
		{
			WSACleanup();
		}
	}
}

/// <summary>
/// 资源释放
/// </summary>
DNSCom::~DNSCom()
{
	if (_success)
	{
		closesocket(_sendsock);
		closesocket(_recvsock);
		WSACleanup();
	}

	_success = false;
	if (_recvdriver.joinable())
		_recvdriver.join();
	if (_senddriver.joinable())
		_senddriver.join();
}

/// <summary>
/// 拉取一个解析后的UDP报文
/// </summary>
/// <returns>解析后的报文（与业务层的通信媒介）</returns>
DNSCom::message_t DNSCom::RecvFrom()
{
	message_t msg;
	if (_success)
	{
		WaitForSingleObject(_recvcounter, 1000);	// 最长等待1S

		_recvlocker.lock();

		if (!_udprecvs.empty())
		{
			msg = _udprecvs.front();
			_udprecvs.pop();
		}

		_recvlocker.unlock();

	}
	return msg;
}

/// <summary>
/// 投递一个待发送的UDP报文所必备的数据
/// </summary>
/// <param name="msg">构建UDP报文的必备信息</param>
void DNSCom::SendTo(const message_t& msg)
{
	if (_success)
	{
		_sendlocker.lock();

		_udpsends.push(msg);
		ReleaseSemaphore(_sendcounter, 0x01, NULL);

		_sendlocker.unlock();
	}
}

/// <summary>
/// 收处理模块
/// </summary>
void DNSCom::_recv()
{
	message_t msg;
	int32_t length;
	SOCKADDR_IN client;
	dns_t udp;
	while (_success)
	{
		length = 0;
		std::memset(&client, 0, sizeof(client));
		std::memset(&udp, 0, sizeof(udp));
		recvfrom(
			_recvsock,
			(LPCH)(&udp), sizeof(dns_t),
			0,
			(LPSOCKADDR)&client, &length
		);

		/* 解析UDP报文 */
		msg = _analyze(udp, client.sin_addr.S_un.S_addr);
		if (msg.type != message_t::type_t::INVALID)
		{	// 有效的UDP报文
			_recvlocker.lock();

			_udprecvs.push(msg);
			ReleaseSemaphore(_recvcounter, 0x01, NULL);

			_recvlocker.unlock();
		}
	}
}

/// <summary>
/// 发处理模块
/// </summary>
void DNSCom::_send()
{
	message_t msg;
	dns_t udp;
	while (_success)
	{
		msg.type = message_t::type_t::INVALID;
		WaitForSingleObject(_sendcounter, 1000);	// 最长等待1S

		_sendlocker.lock();

		if (!_udpsends.empty())
		{
			msg = _udpsends.front();
			_udpsends.pop();
		}

		_sendlocker.unlock();

		switch (msg.type)
		{
		case message_t::type_t::SEND:
			/* 构建UDP包 */
			udp = _analyze(msg);
			break;
		default:
			break;
		}

		std::memset(&_sendaddr, 0, sizeof(_sendaddr));
		_sendaddr.sin_addr.S_un.S_addr = msg.ipv4;
		_sendaddr.sin_family = AF_INET;
		_sendaddr.sin_port = htons(DNS_PORT);
		sendto(
			_sendsock,
			(LPCH)&udp, sizeof(udp.header) + std::strlen(udp.data) + 1,
			0,
			(LPSOCKADDR)&_sendaddr, sizeof(SOCKADDR)
		);
	}
}

/// <summary>
/// 解析UDP报文
/// </summary>
/// <param name="udp">待解析的UDP包</param>
/// <param name="ipv4">源IPv4地址</param>
/// <returns>解析后的数据</returns>
DNSCom::message_t DNSCom::_analyze(const dns_t& udp, ipv4_t ipv4)
{
	message_t msg;
	msg.type = message_t::type_t::RECV;
	msg.ipv4 = _localDnsServer;
	msg.header = udp.header;

	LPCCH front = udp.data;	// 前向指针（逐字节处理）
	LPCCH rear = front;		// 后向指针（配合front进行字符串处理）
	int16_t offset;			// 提取Answer中的Name字段的偏移量
	std::string name;		// Name字段
	int16_t type;			// Type字段
	int16_t cls;			// Class字段
	int32_t ttl;			// TTL
	int16_t length;			// Data Length字段，用以控制ipv4和str的提取
	ipv4_t ipv4;			// 在Type为A模式下有效
	std::string str;		// CNAME、...等模式下有效

	bool error = false;
	/* 提取Question记录 */
	for (int16_t cnt = 0; cnt < udp.header.qdcount; ++cnt)
	{
		// 一串Name字符串的首字节必定为0x03
		if (*front == 0x03)
		{
			front++; // 跳过该字节，该Name字符串以0x00结尾
			while ((rear - udp.data) < DATA_MAXN
				&& *rear != 0x00)
				rear++;

			if (*rear == 0x00)
			{	// 字符串有效
				name.assign(front, rear - front);	// 提取Name字段
				front = rear;
				if (front + 2 * sizeof(int16_t) - udp.data < DATA_MAXN)
				{
					front++;	// 下个字段为Type（A、CNAME、MX...）
					type = *((int16_t*)front);	// 16位
					front += sizeof(int16_t);

					cls = *((int16_t*)front);	// 16位
					front += sizeof(int16_t);

					// 插入一条合法的Question记录
					msg.qs.push_back(
						{
							name,
							(message_t::dns_t)type,
							(message_t::class_t)cls
						}
					);
				}
				else
				{
					error = true;
					break;
				}
			}
			else
			{
				error = true;
				break;
			}
		}
		else
		{
			error = true;
			break;
		}
	}
	if (error)
	{
		// 提取Question字段发生问题，数据作废
		msg.type = message_t::type_t::INVALID;
	}
	else
	{
		/* 提取Answer记录 */
		for (int cnt = 0; cnt < udp.header.ancount; ++cnt)
		{
			offset = *((int16_t*)front) - 0xC000;	// 抓包时观察发现第7位和第5位始终为1
			name.assign(udp.data + offset + 1);		// 通过offset指向DNS报文中该Name已经存在的字段
			front += sizeof(int16_t);				// 16位

			type = *((int16_t*)front);	// Type
			front += sizeof(int16_t);	// 16位

			cls = *((int16_t*)front);	// Class
			front += sizeof(int16_t);	// 16位

			ttl = *((int32_t*)front);	// TTL
			front += sizeof(int32_t);	// 32位

			length = *((int16_t*)front);	// Data Length
			front += sizeof(int16_t);		// 16位

			switch ((message_t::dns_t)type)
			{
			case message_t::dns_t::A:
				if (length == 4)
				{	// IPv4地址
					ipv4 = ntohl(*((int32_t*)front));	// 转小端方式
					front += sizeof(int32_t);
				}
				else
				{
					error = true;
				}
				break;

			case message_t::dns_t::CNAME:
				front++;	// 首字节必定为0x03，跳过该字节
				str.assign(front, length - 1);
				front += length - 1;
				break;

				// TODO 处理其他DNS报文类型AAAA、MX、SOA...

			default:
				error = true;
				break;
			}

			if (error)
			{
				// 提取Answer字段发生问题，数据作废
				msg.type = message_t::type_t::INVALID;
				break;
			}
			else
			{
				// 插入一条合法的Answer记录
				msg.as.push_back(
					{
						name,
						(message_t::dns_t)type,
						(message_t::class_t)cls,
						ttl,
						ipv4,
						str
					}
				);
			}
		}
	}

	return msg;
}

/// <summary>
/// 通过必备的信息来构建UDP报文
/// </summary>
/// <param name="msg">必备数据</param>
/// <remarks>徐逸翔</remarks>
/// <returns>构建好的报文</returns>
DNSCom::dns_t DNSCom::_analyze(const message_t& msg)
{
	dns_t udp;
	// TODO 构建该报文
	// 
	return dns_t();
}
