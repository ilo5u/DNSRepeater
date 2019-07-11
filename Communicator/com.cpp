#include "stdafx.h"
#include "com.h"

#pragma comment(lib, "WS2_32.lib")

/// <summary>
/// DNS端口号
/// </summary>
#define DNS_PORT 53
#define LOC_PORT 47596

/// <summary>
/// 通信环境配置
/// </summary>
/// <param name="_local">本地DNS服务器的IPv4地址</param>
DNSCom::DNSCom(ipv4_t _local) :
	_success(false),
	_localDnsServer(_local),
	_clientlocker(), _locallocker(),
	_recvcounter(nullptr), _sendcounter(nullptr),
	_udprecvs(), _udpsends(),
	_recvclientdriver(), _recvlocaldriver(),
	_senddriver(),
	_clientsock(0x00), _toclientaddr(),
	_localsock(0x00), _tolocaladdr()
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
			_clientsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			_localsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (_clientsock != INVALID_SOCKET
				&& _localsock != INVALID_SOCKET)
			{
				std::memset(&_toclientaddr, 0, sizeof(_toclientaddr));
				_toclientaddr.sin_addr.S_un.S_addr = INADDR_ANY;
				_toclientaddr.sin_family = AF_INET;
				_toclientaddr.sin_port = htons(DNS_PORT);
				ret = bind(_clientsock, (LPSOCKADDR)&_toclientaddr, sizeof(SOCKADDR));
				
				std::memset(&_tolocaladdr, 0, sizeof(_tolocaladdr));
				_tolocaladdr.sin_addr.S_un.S_addr = INADDR_ANY;
				_tolocaladdr.sin_family = AF_INET;
				_tolocaladdr.sin_port = htons(LOC_PORT);
				ret += bind(_localsock, (LPSOCKADDR)&_tolocaladdr, sizeof(SOCKADDR));

				if (ret == 0)
				{
					/* 通信控制组件初始化 */
					_recvcounter = CreateSemaphore(NULL, 0x00, 0xFF, NULL);
					_sendcounter = CreateSemaphore(NULL, 0x00, 0xFF, NULL);

					_success = true;

					_recvclientdriver = std::move(std::thread{ std::bind(&DNSCom::_recvclient , this) });
					_recvlocaldriver = std::move(std::thread{ std::bind(&DNSCom::_recvlocal , this) });
					_senddriver = std::move(std::thread{ std::bind(&DNSCom::_send, this) });
				}
				else
				{
					closesocket(_clientsock);
					closesocket(_localsock);
					WSACleanup();
				}
			}
			else
			{
				closesocket(_clientsock);
				closesocket(_localsock);
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
		closesocket(_clientsock);
		closesocket(_localsock);
		WSACleanup();
	}

	_success = false;
	if (_recvclientdriver.joinable())
		_recvclientdriver.join();
	if (_recvlocaldriver.joinable())
		_recvlocaldriver.join();
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

		_clientlocker.lock();

		if (!_udprecvs.empty())
		{
			msg = _udprecvs.front();
			_udprecvs.pop();
		}

		_clientlocker.unlock();

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
		_locallocker.lock();

		_udpsends.push(msg);
		ReleaseSemaphore(_sendcounter, 0x01, NULL);

		_locallocker.unlock();
	}
}

/// <summary>
/// 收处理模块
/// </summary>
void DNSCom::_recvclient()
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
			_clientsock,
			(LPCH)(&udp), sizeof(dns_t),
			0,
			(LPSOCKADDR)&client, (int*)&udp.length
		);
		if (udp.length > 0)
		{
			/* 解析UDP报文 */
			msg = _analyze(udp, ntohl(client.sin_addr.S_un.S_addr), ntohs(client.sin_port));
			if (msg.type != message_t::type_t::INVALID)
			{	// 有效的UDP报文
				_clientlocker.lock();

				_udprecvs.push(msg);
				ReleaseSemaphore(_recvcounter, 0x01, NULL);

				_clientlocker.unlock();
			}
		}
		else
		{
			udp.length = WSAGetLastError();
		}
	}
}

/// <summary>
/// 收处理模块
/// </summary>
void DNSCom::_recvlocal()
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
			_localsock,
			(LPCH)(&udp), sizeof(dns_t),
			0,
			(LPSOCKADDR)&client, (int*)&udp.length
		);
		if (udp.length > 0)
		{
			/* 解析UDP报文 */
			msg = _analyze(udp, ntohl(client.sin_addr.S_un.S_addr), ntohs(client.sin_port));
			if (msg.type != message_t::type_t::INVALID)
			{	// 有效的UDP报文
				_clientlocker.lock();

				_udprecvs.push(msg);
				ReleaseSemaphore(_recvcounter, 0x01, NULL);

				_clientlocker.unlock();
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
	SOCKADDR_IN sendaddr;
	int ret = 0;
	while (_success)
	{
		msg.type = message_t::type_t::INVALID;
		WaitForSingleObject(_sendcounter, 1000);	// 最长等待1S

		_locallocker.lock();

		if (!_udpsends.empty())
		{
			msg = _udpsends.front();
			_udpsends.pop();
		}

		_locallocker.unlock();

		switch (msg.type)
		{
		case message_t::type_t::SEND:
			/* 构建UDP包 */
			udp = _analyze(msg);

			std::memset(&sendaddr, 0, sizeof(sendaddr));
			sendaddr.sin_addr.S_un.S_addr = htonl(msg.ipv4);
			sendaddr.sin_port = htons(msg.port);
			sendaddr.sin_family = AF_INET;
			if (msg.ipv4 == _localDnsServer)
			{
				ret = sendto(
					_localsock,
					(LPCH)&udp, udp.length,
					0,
					(LPSOCKADDR)&sendaddr, sizeof(SOCKADDR)
				);
			}
			else
			{
				ret = sendto(
					_clientsock,
					(LPCH)&udp, udp.length,
					0,
					(LPSOCKADDR)&sendaddr, sizeof(SOCKADDR)
				);
			}
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
static std::string findstr(const char data[], uint16_t offset)
{
	std::string partial;
	LPCCH front = data + offset;
	int8_t behinds = 0;
	while (*front != 0x00)
	{
		if ((*front & 0xC0) == 0xC0)
		{
			// 偏移量结尾
			partial.append(findstr(data, (ntohs(*((uint16_t*)front)) & 0x3FFF) - 0x0C));
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
	if (!partial.empty()
		&& partial.back() == '.')
		partial.pop_back();

	return partial;
}

/// <summary>
/// 解析UDP报文
/// </summary>
/// <param name="udp">待解析的UDP包</param>
/// <param name="ipv4">源IPv4地址</param>
/// <returns>解析后的数据</returns>
DNSCom::message_t DNSCom::_analyze(const dns_t& udp, ipv4_t srcipv4, port_t srcport)
{
	message_t msg;
	msg.type = message_t::type_t::RECV;
	msg.ipv4 = srcipv4;
	msg.port = srcport;
	msg.header = udp.header;

	msg.header.id = ntohs(msg.header.id);
	*((uint16_t*)&msg.header.flags) = ntohs(*((uint16_t*)&msg.header.flags));
	msg.header.qdcount = ntohs(msg.header.qdcount);
	msg.header.ancount = ntohs(msg.header.ancount);
	msg.header.nscount = ntohs(msg.header.nscount);
	msg.header.arcount = ntohs(msg.header.arcount);

	LPCCH front = udp.data;	// 前向指针（逐字节处理）
	LPCCH rear = front;		// 后向指针（配合front进行字符串处理）
	message_t::question_t question;
	message_t::answer_t answer;
	message_t::nameserver_t nameserver;
	bool offset;

	bool error = false;
	/* 提取Question记录 */
	for (uint16_t cnt = 0; cnt < msg.header.qdcount; ++cnt)
	{
		question.name = findstr(udp.data, front - udp.data);
		offset = false;
		while (*front != 0x00)
		{
			if ((*front & 0xC0) == 0xC0)
			{
				// 偏移量结尾
				front += sizeof(uint16_t);
				offset = true;
				break;
			}
			else
			{
				// 后续字符个数记录
				front += (*front + 1);
			}
		}
		if (!offset)
			front++;

		if (front + 2 * sizeof(uint16_t) - udp.data < DATA_MAXN)
		{
			// 下个字段为Type（A、CNAME、MX...）
			question.dnstype = (message_t::dns_t)ntohs(*((uint16_t*)front));	// 16位
			front += sizeof(uint16_t);

			question.cls = (message_t::class_t)ntohs(*((uint16_t*)front));	// 16位
			front += sizeof(uint16_t);

			// 插入一条合法的Question记录
			msg.qs.push_back(question);
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
			answer.name = findstr(udp.data, front - udp.data);
			offset = false;
			while (*front != 0x00)
			{
				if ((*front & 0xC0) == 0xC0)
				{
					// 偏移量结尾
					front += sizeof(uint16_t);
					offset = true;
					break;
				}
				else
				{
					// 后续字符个数记录
					front += (*front + 1);
				}
			}
			if (!offset)
				front++;

			answer.dnstype = (message_t::dns_t)ntohs(*((uint16_t*)front));	// Type
			front += sizeof(uint16_t);	// 16位

			answer.cls = (message_t::class_t)ntohs(*((uint16_t*)front));	// Class
			front += sizeof(uint16_t);	// 16位

			answer.ttl = ntohl(*((uint32_t*)front));	// TTL
			front += sizeof(uint32_t);	// 32位

			answer.datalength = ntohs(*((uint16_t*)front));	// Data Length
			front += sizeof(uint16_t);		// 16位

			switch (answer.dnstype)
			{
			case message_t::dns_t::A:
				if (answer.datalength == 4)
				{	// IPv4地址
					answer.ipv4 = ntohl(*((uint32_t*)front));	// 转小端方式
					front += sizeof(uint32_t);
				}
				else
				{
					error = true;
				}
				break;
			
			case message_t::dns_t::NS:
			case message_t::dns_t::CNAME:
				// 递归提取CNAME字段
				answer.str = findstr(udp.data, front - udp.data);
				offset = false;
				while (*front != 0x00)
				{
					if ((*front & 0xC0) == 0xC0)
					{
						// 偏移量结尾
						front += sizeof(uint16_t);
						offset = true;
						break;
					}
					else
					{
						// 后续字符个数记录
						front += (*front + 1);
					}
				}
				if (!offset)
					front++;
				break;

			case message_t::dns_t::MX:
				// 提取Preference字段
				answer.preference = ntohs(*((uint16_t*)front));
				front += sizeof(uint16_t);

				// 递归提取Mail Exchange字段
				answer.str = findstr(udp.data, front - udp.data);
				offset = false;
				while (*front != 0x00)
				{
					if ((*front & 0xC0) == 0xC0)
					{
						// 偏移量结尾
						front += sizeof(uint16_t);
						offset = true;
						break;
					}
					else
					{
						// 后续字符个数记录
						front += (*front + 1);
					}
				}
				if (!offset)
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
				msg.as.push_back(answer);
			}
		}

		if (error)
		{
			// 提取Answer字段发生问题，数据作废
			msg.type = message_t::type_t::INVALID;
		}
		else
		{
			/* 提取Nameserver记录 */
			for (int cnt = 0; cnt < msg.header.nscount; ++cnt)
			{
				// 递归提取Name字段
				nameserver.name = findstr(udp.data, front - udp.data);
				offset = false;
				while (*front != 0x00)
				{
					if ((*front & 0xC0) == 0xC0)
					{
						// 偏移量结尾
						front += sizeof(uint16_t);
						offset = true;
						break;
					}
					else
					{
						// 后续字符个数记录
						front += (*front + 1);
					}
				}
				if (!offset)
					front++;

				nameserver.dnstype = (message_t::dns_t)ntohs(*((uint16_t*)front));	// Type
				front += sizeof(uint16_t);	// 16位

				nameserver.cls = (message_t::class_t)ntohs(*((uint16_t*)front));	// Class
				front += sizeof(uint16_t);	// 16位

				nameserver.ttl = ntohl(*((uint32_t*)front));	// TTL
				front += sizeof(uint32_t);	// 32位

				nameserver.datalength = ntohs(*((uint16_t*)front));	// Data Length
				front += sizeof(uint16_t);		// 16位

				switch (nameserver.dnstype)
				{
				case message_t::dns_t::SOA:
					// 递归提取Primary name server字段
					nameserver.primary = findstr(udp.data, front - udp.data);
					offset = false;
					while (*front != 0x00)
					{
						if ((*front & 0xC0) == 0xC0)
						{
							// 偏移量结尾
							front += sizeof(uint16_t);
							offset = true;
							break;
						}
						else
						{
							// 后续字符个数记录
							front += (*front + 1);
						}
					}
					if (!offset)
						front++;

					nameserver.mailbox = findstr(udp.data, front - udp.data);
					offset = false;
					while (*front != 0x00)
					{
						if ((*front & 0xC0) == 0xC0)
						{
							// 偏移量结尾
							front += sizeof(uint16_t);
							offset = true;
							break;
						}
						else
						{
							// 后续字符个数记录
							front += (*front + 1);
						}
					}
					if (!offset)
						front++;

					nameserver.number = ntohl(*((uint32_t*)front));	// Serial Number
					front += sizeof(uint32_t);	// 32位

					nameserver.refresh = ntohl(*((uint32_t*)front));	// Refresh Interval
					front += sizeof(uint32_t);	// 32位

					nameserver.retry = ntohl(*((uint32_t*)front));	// Retry Interval
					front += sizeof(uint32_t);	// 32位

					nameserver.limit = ntohl(*((uint32_t*)front));	// Expire limit
					front += sizeof(uint32_t);	// 32位

					nameserver.minttl = ntohl(*((uint32_t*)front));	// Minimal TTL
					front += sizeof(uint32_t);	// 32位

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
					msg.ns.push_back(nameserver);
				}
			}
		}
	}

	return msg;
}

/// <summary>
/// 构造DNS报文中的字符串表达形式
/// </summary>
/// <param name="src">待构造的字符串</param>
/// <returns>构造好的字符串</returns>
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
	*((uint16_t*)&udp.header.flags) = htons(*((uint16_t*)&udp.header.flags));
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

		*((uint16_t*)front) = htons((uint16_t)record.dnstype);
		front += sizeof(uint16_t);

		*((uint16_t*)front) = htons((uint16_t)record.cls);
		front += sizeof(uint16_t);
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

		*((uint16_t*)front) = htons((uint16_t)record.dnstype);
		front += sizeof(uint16_t);

		*((uint16_t*)front) = htons((uint16_t)record.cls);
		front += sizeof(uint16_t);

		*((uint32_t*)front) = htonl((uint32_t)record.ttl);
		front += sizeof(uint32_t);

		datalength = front;
		front += sizeof(uint16_t);

		switch (record.dnstype)
		{
		case message_t::dns_t::A:
			*((uint32_t*)front) = htonl((uint32_t)record.ipv4);
			front += sizeof(uint32_t);

			*((uint16_t*)datalength) = htons((uint16_t)sizeof(uint32_t));
			break;

		case message_t::dns_t::NS:
		case message_t::dns_t::CNAME:
			prefix = buildstr(record.str);
			std::strcpy(front, prefix.c_str());
			front += prefix.size();
			*front = 0x0;
			front++;

			*((uint16_t*)datalength) = htons((uint16_t)prefix.size() + 1);
			break;

		case message_t::dns_t::MX:
			*((uint16_t*)front) = htons((uint16_t)record.preference);
			front += sizeof(uint16_t);

			prefix = buildstr(record.str);
			std::strcpy(front, prefix.c_str());
			front += prefix.size();
			*front = 0x0;
			front++;

			*((uint16_t*)datalength) = htons((uint16_t)prefix.size() + 1 + sizeof(uint16_t));
			break;
		default:
			break;
		}
	}
	udp.length = front - udp.data + sizeof(dns_t::header_t);

	// 构造Nameserver字段
	datalength = front;
	for (const auto& record : msg.ns)
	{
		prefix = buildstr(record.name);
		std::strcpy(front, prefix.c_str());
		front += prefix.size();
		*front = 0x0;
		front++;

		*((uint16_t*)front) = htons((uint16_t)record.dnstype);
		front += sizeof(uint16_t);

		*((uint16_t*)front) = htons((uint16_t)record.cls);
		front += sizeof(uint16_t);

		*((uint32_t*)front) = htonl((uint32_t)record.ttl);
		front += sizeof(uint32_t);

		datalength = front;
		front += sizeof(uint16_t);

		LPCH start = front;
		switch (record.dnstype)
		{
		case message_t::dns_t::SOA:
			prefix = buildstr(record.primary);
			std::strcpy(front, prefix.c_str());
			front += prefix.size();
			*front = 0x0;
			front++;

			prefix = buildstr(record.mailbox);
			std::strcpy(front, prefix.c_str());
			front += prefix.size();
			*front = 0x0;
			front++;

			*((uint32_t*)front) = htonl((uint32_t)record.number);
			front += sizeof(uint32_t);

			*((uint32_t*)front) = htonl((uint32_t)record.refresh);
			front += sizeof(uint32_t);

			*((uint32_t*)front) = htonl((uint32_t)record.retry);
			front += sizeof(uint32_t);

			*((uint32_t*)front) = htonl((uint32_t)record.limit);
			front += sizeof(uint32_t);

			*((uint32_t*)front) = htonl((uint32_t)record.minttl);
			front += sizeof(uint32_t);

			*((uint16_t*)datalength) = htons(front - start);
			break;

		default:
			break;
		}
	}
	udp.length = front - udp.data + sizeof(dns_t::header_t);

	return udp;
}
