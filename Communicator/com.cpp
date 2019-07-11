#include "stdafx.h"
#include "com.h"

#pragma comment(lib, "WS2_32.lib")

/// <summary>
/// Ĭ��ʹ�õ��м�DNS��������IPv4��ַ
/// </summary>
#define LOOP_IPADDR "127.0.0.1"
#define HOST_IPADDR "10.128.223.253"

/// <summary>
/// DNS�˿ں�
/// </summary>
#define DNS_PORT 53
#define LOC_PORT 47596

/// <summary>
/// ͨ�Ż�������
/// </summary>
/// <param name="_local">����DNS��������IPv4��ַ</param>
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
			/* �׽��ֳ�ʼ�� */
			_clientsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			_testsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			_localsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (_clientsock != INVALID_SOCKET
				&& _localsock != INVALID_SOCKET)
			{
				std::memset(&_toclientaddr, 0, sizeof(_toclientaddr));
				_toclientaddr.sin_addr.S_un.S_addr = inet_addr(LOOP_IPADDR);
				_toclientaddr.sin_family = AF_INET;
				_toclientaddr.sin_port = htons(DNS_PORT);
				ret = bind(_clientsock, (LPSOCKADDR)&_toclientaddr, sizeof(SOCKADDR));

				std::memset(&_toclientaddr, 0, sizeof(_toclientaddr));
				_toclientaddr.sin_addr.S_un.S_addr = INADDR_ANY;
				_toclientaddr.sin_family = AF_INET;
				_toclientaddr.sin_port = htons(32457);
				ret += bind(_testsock, (LPSOCKADDR)&_toclientaddr, sizeof(SOCKADDR));
				
				std::memset(&_tolocaladdr, 0, sizeof(_tolocaladdr));
				_tolocaladdr.sin_addr.S_un.S_addr = INADDR_ANY;
				_tolocaladdr.sin_family = AF_INET;
				_tolocaladdr.sin_port = htons(LOC_PORT);
				ret += bind(_localsock, (LPSOCKADDR)&_tolocaladdr, sizeof(SOCKADDR));

				if (ret == 0)
				{
					/* ͨ�ſ��������ʼ�� */
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
/// ��Դ�ͷ�
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
/// ��ȡһ���������UDP����
/// </summary>
/// <returns>������ı��ģ���ҵ����ͨ��ý�飩</returns>
DNSCom::message_t DNSCom::RecvFrom()
{
	message_t msg;
	if (_success)
	{
		WaitForSingleObject(_recvcounter, 1000);	// ��ȴ�1S

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
/// Ͷ��һ�������͵�UDP�������ر�������
/// </summary>
/// <param name="msg">����UDP���ĵıر���Ϣ</param>
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
/// �մ���ģ��
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
			(LPSOCKADDR)&client, &udp.length
		);
		if (udp.length > 0)
		{
			/* ����UDP���� */
			msg = _analyze(udp, ntohl(client.sin_addr.S_un.S_addr), ntohs(client.sin_port));
			if (msg.type != message_t::type_t::INVALID)
			{	// ��Ч��UDP����
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
/// �մ���ģ��
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
			(LPSOCKADDR)&client, &udp.length
		);
		if (udp.length > 0)
		{
			/* ����UDP���� */
			msg = _analyze(udp, ntohl(client.sin_addr.S_un.S_addr), ntohs(client.sin_port));
			if (msg.type != message_t::type_t::INVALID)
			{	// ��Ч��UDP����
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
/// ������ģ��
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
		WaitForSingleObject(_sendcounter, 1000);	// ��ȴ�1S

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
			/* ����UDP�� */
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
				ret = WSAGetLastError();
			}
			break;
		default:
			break;
		}
	}
}

/// <summary>
/// �ݹ������ѹ�����ַ���
/// �ַ��������ַ�ʽ����
/// 1.[����n](8λ)[n���ַ�](8nλ)...[����m=0]
/// 2.[����n](8λ)[n���ַ�](8nλ)...[ƫ����](16λ)(����11xxxxxx)
/// 3.[ƫ����](16λ)(����11xxxxxx)
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
			// ƫ������β
			partial.append(findstr(data, (ntohs(*((int16_t*)front)) & 0x3FFF) - 0x0C));
			break;
		}
		else
		{
			// �����ַ�������¼
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
/// ����UDP����
/// </summary>
/// <param name="udp">��������UDP��</param>
/// <param name="ipv4">ԴIPv4��ַ</param>
/// <returns>�����������</returns>
DNSCom::message_t DNSCom::_analyze(const dns_t& udp, ipv4_t srcipv4, port_t srcport)
{
	message_t msg;
	msg.type = message_t::type_t::RECV;
	msg.ipv4 = srcipv4;
	msg.port = srcport;
	msg.header = udp.header;

	msg.header.id = ntohs(msg.header.id);
	*((int16_t*)&msg.header.flags) = ntohs(*((int16_t*)&msg.header.flags));
	msg.header.qdcount = ntohs(msg.header.qdcount);
	msg.header.ancount = ntohs(msg.header.ancount);
	msg.header.nscount = ntohs(msg.header.nscount);
	msg.header.arcount = ntohs(msg.header.arcount);

	LPCCH front = udp.data;	// ǰ��ָ�루���ֽڴ���
	LPCCH rear = front;		// ����ָ�루���front�����ַ�������
	std::string name;		// Name�ֶ�
	int16_t type;			// Type�ֶ�
	int16_t cls;			// Class�ֶ�
	int32_t ttl;			// TTL
	int16_t length;			// Data Length�ֶΣ����Կ���ipv4��str����ȡ
	ipv4_t ipv4{ 0 };		// ��TypeΪAģʽ����Ч
	int16_t preference{ 0 };	// ��MXģʽ����Ч
	std::string str;		// CNAME��...��ģʽ����Ч
	bool offset;

	bool error = false;
	/* ��ȡQuestion��¼ */
	for (int16_t cnt = 0; cnt < msg.header.qdcount; ++cnt)
	{
		name = findstr(udp.data, front - udp.data);
		offset = false;
		while (*front != 0x00)
		{
			if ((*front & 0xC0) == 0xC0)
			{
				// ƫ������β
				front += sizeof(int16_t);
				offset = true;
				break;
			}
			else
			{
				// �����ַ�������¼
				front += (*front + 1);
			}
		}
		if (!offset)
			front++;

		if (front + 2 * sizeof(int16_t) - udp.data < DATA_MAXN)
		{
			// �¸��ֶ�ΪType��A��CNAME��MX...��
			type = ntohs(*((int16_t*)front));	// 16λ
			front += sizeof(int16_t);

			cls = ntohs(*((int16_t*)front));	// 16λ
			front += sizeof(int16_t);

			// ����һ���Ϸ���Question��¼
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
		// ��ȡQuestion�ֶη������⣬��������
		msg.type = message_t::type_t::INVALID;
	}
	else
	{
		/* ��ȡAnswer��¼ */
		for (int cnt = 0; cnt < msg.header.ancount; ++cnt)
		{
			// �ݹ���ȡName�ֶ�
			name = findstr(udp.data, front - udp.data);
			offset = false;
			while (*front != 0x00)
			{
				if ((*front & 0xC0) == 0xC0)
				{
					// ƫ������β
					front += sizeof(int16_t);
					offset = true;
					break;
				}
				else
				{
					// �����ַ�������¼
					front += (*front + 1);
				}
			}
			if (!offset)
				front++;

			type = ntohs(*((int16_t*)front));	// Type
			front += sizeof(int16_t);	// 16λ

			cls = ntohs(*((int16_t*)front));	// Class
			front += sizeof(int16_t);	// 16λ

			ttl = ntohl(*((int32_t*)front));	// TTL
			front += sizeof(int32_t);	// 32λ

			length = ntohs(*((int16_t*)front));	// Data Length
			front += sizeof(int16_t);		// 16λ

			switch ((message_t::dns_t)type)
			{
			case message_t::dns_t::A:
				if (length == 4)
				{	// IPv4��ַ
					ipv4 = ntohl(*((int32_t*)front));	// תС�˷�ʽ
					front += sizeof(int32_t);
				}
				else
				{
					error = true;
				}
				break;

			case message_t::dns_t::NS:
			case message_t::dns_t::CNAME:
				// �ݹ���ȡCNAME�ֶ�
				str = findstr(udp.data, front - udp.data);
				offset = false;
				while (*front != 0x00)
				{
					if ((*front & 0xC0) == 0xC0)
					{
						// ƫ������β
						front += sizeof(int16_t);
						offset = true;
						break;
					}
					else
					{
						// �����ַ�������¼
						front += (*front + 1);
					}
				}
				if (!offset)
					front++;
				break;

			case message_t::dns_t::MX:
				// ��ȡPreference�ֶ�
				preference = ntohs(*((int16_t*)front));
				front += sizeof(int16_t);

				// �ݹ���ȡMail Exchange�ֶ�
				str = findstr(udp.data, front - udp.data);
				offset = false;
				while (*front != 0x00)
				{
					if ((*front & 0xC0) == 0xC0)
					{
						// ƫ������β
						front += sizeof(int16_t);
						offset = true;
						break;
					}
					else
					{
						// �����ַ�������¼
						front += (*front + 1);
					}
				}
				if (!offset)
					front++;
				break;

				// TODO ��������DNS��������AAAA��MX��SOA...

			default:
				error = true;
				break;
			}

			if (error)
			{
				// ��ȡAnswer�ֶη������⣬��������
				msg.type = message_t::type_t::INVALID;
				break;
			}
			else
			{
				// ����һ���Ϸ���Answer��¼
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
			// ��ȡAnswer�ֶη������⣬��������
			msg.type = message_t::type_t::INVALID;
		}
		else
		{

		}
	}

	return msg;
}
/// <summary>
/// ����DNS�����е��ַ��������ʽ
/// </summary>
/// <param name="src">��������ַ���</param>
/// <returns>����õ��ַ���</returns>
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
/// ͨ���ر�����Ϣ������UDP����
/// </summary>
/// <param name="msg">�ر�����</param>
/// <remarks>������</remarks>
/// <returns>�����õı���</returns>
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

	// ����Query�ֶ�
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
	// ����Answer�ֶ�
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

			*((int16_t*)datalength) = htons((int16_t)sizeof(int32_t));
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
