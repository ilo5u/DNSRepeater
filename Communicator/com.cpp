#include "stdafx.h"
#include "com.h"

#pragma comment(lib, "WS2_32.lib")

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
			_recvsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			_sendsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (_recvsock != INVALID_SOCKET
				&& _sendsock != INVALID_SOCKET)
			{
				std::memset(&_recvaddr, 0, sizeof(_recvaddr));
				_recvaddr.sin_addr.S_un.S_addr = inet_addr(HOST_IPADDR);
				_recvaddr.sin_family = AF_INET;
				_recvaddr.sin_port = htons(DNS_PORT);

				ret = bind(_recvsock, (LPSOCKADDR)&_recvaddr, sizeof(SOCKADDR));
				if (ret == 0)
				{
					/* 通信控制组件初始化 */
					_recvcounter = CreateSemaphore(NULL, 0x00, 0xFF, NULL);
					_sendcounter = CreateSemaphore(NULL, 0x00, 0xFF, NULL);

					_success = true;

					_recvdriver = std::move(std::thread{ std::bind(&DNSCom::_recv, this) });
					_senddriver = std::move(std::thread{ std::bind(&DNSCom::_send, this) });
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
	SOCKADDR_IN client;
	dns_t udp;
	// int ret;
	while (_success)
	{
		std::memset(&client, 0, sizeof(client));
		std::memset(&udp, 0, sizeof(udp));
		udp.length = sizeof(SOCKADDR);
		udp.length = recvfrom(
			_recvsock,
			(LPCH)(&udp), sizeof(dns_t),
			0,
			(LPSOCKADDR)&client, &udp.length
		);
		if (udp.length > 0)
		{
			/* 解析UDP报文 */
			msg = _analyze(udp, ntohl(client.sin_addr.S_un.S_addr));
			if (msg.type != message_t::type_t::INVALID)
			{	// 有效的UDP报文
				_recvlocker.lock();

				_udprecvs.push(msg);
				ReleaseSemaphore(_recvcounter, 0x01, NULL);

				_recvlocker.unlock();
			}
		}
		else
		{
			udp.length = WSAGetLastError();
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

			std::memset(&_sendaddr, 0, sizeof(_sendaddr));
			_sendaddr.sin_addr.S_un.S_addr = msg.ipv4;
			_sendaddr.sin_family = AF_INET;
			_sendaddr.sin_port = htons(DNS_PORT);
			sendto(
				_sendsock,
				(LPCH)&udp, udp.length,
				0,
				(LPSOCKADDR)&_sendaddr, sizeof(SOCKADDR)
			);
			break;
		default:
			break;
		}
	}
}

/// <summary>
/// 递归解析被压缩的字符串
/// 字符串有三种方式构成
/// 1.[计数n](8位)[n个字符](8n位)...[计数m=0]
/// 2.[计数n](8位)[n个字符](8n位)...[偏移量](16位)(形如11xxxxxx)
/// 3.[偏移量](16位)(形如11xxxxxx)
/// </summary>
/// <param name="data"></param>
/// <param name="offset"></param>
/// <returns></returns>
static std::string findstr(const char data[], int16_t offset)
{
	std::string partial;
	LPCCH front = data + offset;
	int8_t behinds = 0;
	while (*front != 0x00)
	{
		if ((*front & 0xC0) == 0xC0)
		{
			// 偏移量结尾
			partial.append(findstr(data, (*front & 0x3F)));
			break;
		}
		else
		{
			// 后续字符字数记录
			behinds = *front;
			front++;

			while (behinds--)
			{
				partial.push_back(*front);
				front++;
			}
			partial.push_back('.');
		}
	}
	if (!partial.empty())
		partial.pop_back();

	return partial;
}

/// <summary>
/// 解析UDP报文
/// </summary>
/// <param name="udp">待解析的UDP包</param>
/// <param name="ipv4">源IPv4地址</param>
/// <returns>解析后的数据</returns>
DNSCom::message_t DNSCom::_analyze(const dns_t& udp, ipv4_t srcipv4)
{
	message_t msg;
	msg.type = message_t::type_t::RECV;
	msg.ipv4 = srcipv4;
	msg.header = udp.header;

	msg.header.id = ntohs(msg.header.id);
	*((int16_t*)&msg.header.flags) = ntohs(*((int16_t*)&msg.header.flags));
	msg.header.qdcount = ntohs(msg.header.qdcount);
	msg.header.ancount = ntohs(msg.header.ancount);
	msg.header.nscount = ntohs(msg.header.nscount);
	msg.header.arcount = ntohs(msg.header.arcount);

	LPCCH front = udp.data;	// 前向指针（逐字节处理）
	LPCCH rear = front;		// 后向指针（配合front进行字符串处理）
	std::string name;		// Name字段
	int16_t type;			// Type字段
	int16_t cls;			// Class字段
	int32_t ttl;			// TTL
	int16_t length;			// Data Length字段，用以控制ipv4和str的提取
	ipv4_t ipv4;			// 在Type为A模式下有效
	int16_t preference;		// 在MX模式下有效
	std::string str;		// CNAME、...等模式下有效

	bool error = false;
	/* 提取Question记录 */
	for (int16_t cnt = 0; cnt < msg.header.qdcount; ++cnt)
	{
		name = findstr(udp.data, front - udp.data);
		while (*front != 0x00)
		{
			if ((*front & 0xC0) == 0xC0)
			{
				// 偏移量结尾
				front += sizeof(int16_t);
				break;
			}
			else
			{
				// 后续字符个数记录
				front += (*front + 1);
			}
		}
		if (*front == 0x00)
			front++;

		if (front + 2 * sizeof(int16_t) - udp.data < DATA_MAXN)
		{
			// 下个字段为Type（A、CNAME、MX...）
			type = ntohs(*((int16_t*)front));	// 16位
			front += sizeof(int16_t);

			cls = ntohs(*((int16_t*)front));	// 16位
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

	if (error)
	{
		// 提取Question字段发生问题，数据作废
		msg.type = message_t::type_t::INVALID;
	}
	else
	{
		/* 提取Answer记录 */
		for (int cnt = 0; cnt < msg.header.ancount; ++cnt)
		{
			// 递归提取Name字段
			name = findstr(udp.data, *front);
			while (*front != 0x00)
			{
				if ((*front & 0xC0) == 0xC0)
				{
					// 偏移量结尾
					front += sizeof(int16_t);
					break;
				}
				else
				{
					// 后续字符个数记录
					front += (*front + 1);
				}
			}
			if (*front == 0x00)
				front++;

			type = ntohs(*((int16_t*)front));	// Type
			front += sizeof(int16_t);	// 16位

			cls = ntohs(*((int16_t*)front));	// Class
			front += sizeof(int16_t);	// 16位

			ttl = ntohl(*((int32_t*)front));	// TTL
			front += sizeof(int32_t);	// 32位

			length = ntohs(*((int16_t*)front));	// Data Length
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
			
			case message_t::dns_t::NS:
			case message_t::dns_t::CNAME:
				// 递归提取CNAME字段
				str = findstr(udp.data, *front);
				while (*front != 0x00)
				{
					if ((*front & 0xC0) == 0xC0)
					{
						// 偏移量结尾
						front += sizeof(int16_t);
						break;
					}
					else
					{
						// 后续字符个数记录
						front += (*front + 1);
					}
				}
				if (*front == 0x00)
					front++;
				break;

			case message_t::dns_t::MX:
				// 提取Preference字段
				preference = ntohs(*((int16_t*)front));
				front += sizeof(int16_t);

				// 递归提取Mail Exchange字段
				str = findstr(udp.data, *front);
				while (*front != 0x00)
				{
					if ((*front & 0xC0) == 0xC0)
					{
						// 偏移量结尾
						front += sizeof(int16_t);
						break;
					}
					else
					{
						// 后续字符个数记录
						front += (*front + 1);
					}
				}
				if (*front == 0x00)
					front++;
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
						preference,
						str
					}
				);
			}
		}

		if (error)
		{
			// 提取Answer字段发生问题，数据作废
			msg.type = message_t::type_t::INVALID;
		}
		else
		{

		}
	}

	return msg;
}

std::string buildstr(const std::string& src)
{
	std::string target;
	int8_t cnt = 0;
	for (std::string::const_iterator front = src.begin(), rear = src.begin(); front != src.end(); cnt = 0, rear = front)
	{
		while (rear != src.end() && *rear != '.')
			rear++, cnt++;
	
		target.push_back(cnt);

		while (front != rear)
		{
			target.push_back(*front);
			front++;
		}

		if (front != src.end())
			front++;
	}
	return target;
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
	udp.header = msg.header;

	udp.header.id = htons(udp.header.id);
	*((int16_t*)&udp.header.flags) = htons(*((int16_t*)&udp.header.flags));
	udp.header.qdcount = htons(udp.header.qdcount);
	udp.header.ancount = htons(udp.header.ancount);
	udp.header.arcount = htons(udp.header.arcount);
	udp.header.nscount = htons(udp.header.nscount);

	LPCH front = udp.data;
	std::string prefix;

	// 构造Query字段
	for (const auto& record : msg.qs)
	{
		prefix = buildstr(record.name);
		std::strcpy(front, prefix.c_str());
		front += prefix.size();
		*front = 0x0;
		front++;

		*((int16_t*)front) = htons((int16_t)record.dnstype);
		front += sizeof(int16_t);

		*((int16_t*)front) = htons((int16_t)record.cls);
		front += sizeof(int16_t);
	}
	// 构造Answer字段
	LPCH datalength = front;
	for (const auto& record : msg.as)
	{
		prefix = buildstr(record.name);
		std::strcpy(front, prefix.c_str());
		front += prefix.size();
		*front = 0x0;
		front++;

		*((int16_t*)front) = htons((int16_t)record.dnstype);
		front += sizeof(int16_t);

		*((int16_t*)front) = htons((int16_t)record.cls);
		front += sizeof(int16_t);

		*((int32_t*)front) = htonl((int32_t)record.ttl);
		front += sizeof(int32_t);

		datalength = front;
		front += sizeof(int16_t);

		switch (record.dnstype)
		{
		case message_t::dns_t::A:
			*((int32_t*)front) = htonl((int32_t)record.ipv4);
			front += sizeof(int32_t);

			*((int16_t*)datalength) = htons(sizeof(int32_t));
			break;

		case message_t::dns_t::NS:
		case message_t::dns_t::CNAME:
			prefix = buildstr(record.str);
			std::strcpy(front, prefix.c_str());
			front += prefix.size();
			*front = 0x0;
			front++;

			*((int16_t*)datalength) = htons((int16_t)prefix.size() + 1);
			break;

		case message_t::dns_t::MX:
			*((int16_t*)front) = htons((int16_t)record.preference);
			front += sizeof(int16_t);

			prefix = buildstr(record.str);
			std::strcpy(front, prefix.c_str());
			front += prefix.size();
			*front = 0x0;
			front++;

			*((int16_t*)datalength) = htons((int16_t)prefix.size() + 1);
			break;
		default:
			break;
		}
	}
	udp.length = front - udp.data + sizeof(dns_t::header_t);

	return udp;
}
