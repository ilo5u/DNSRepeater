#include "stdafx.h"
#include "com.h"

/// <summary>
/// Ĭ��ʹ�õ��м�DNS��������IPv4��ַ
/// </summary>
#define HOST_IPADDR "127.0.0.1"

/// <summary>
/// DNS�˿ں�
/// </summary>
#define DNS_PORT 53

/// <summary>
/// ͨ�Ż�������
/// </summary>
/// <param name="_local">����DNS��������IPv4��ַ</param>
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
			/* �׽��ֳ�ʼ�� */
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
					/* ͨ�ſ��������ʼ�� */
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
/// ��Դ�ͷ�
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
/// ��ȡһ���������UDP����
/// </summary>
/// <returns>������ı��ģ���ҵ����ͨ��ý�飩</returns>
DNSCom::message_t DNSCom::RecvFrom()
{
	message_t msg;
	if (_success)
	{
		WaitForSingleObject(_recvcounter, 1000);	// ��ȴ�1S

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
/// Ͷ��һ�������͵�UDP�������ر�������
/// </summary>
/// <param name="msg">����UDP���ĵıر���Ϣ</param>
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
/// �մ���ģ��
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

		/* ����UDP���� */
		msg = _analyze(udp, client.sin_addr.S_un.S_addr);
		if (msg.type != message_t::type_t::INVALID)
		{	// ��Ч��UDP����
			_recvlocker.lock();

			_udprecvs.push(msg);
			ReleaseSemaphore(_recvcounter, 0x01, NULL);

			_recvlocker.unlock();
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
	while (_success)
	{
		msg.type = message_t::type_t::INVALID;
		WaitForSingleObject(_sendcounter, 1000);	// ��ȴ�1S

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
			/* ����UDP�� */
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
/// �ݹ������ѹ�����ַ���
/// �ַ��������ַ�ʽ����
/// 1.[����n](8λ)[n���ַ�](8nλ)...[����m=0]
/// 2.[����n](8λ)[n���ַ�](8nλ)...[ƫ����](16λ)(����11xxxxxx)
/// 3.[ƫ����](16λ)(����11xxxxxx)
/// </summary>
/// <param name="data"></param>
/// <param name="offset"></param>
/// <returns></returns>
static std::string findname(const char data[], int16_t offset)
{
	std::string partial;
	LPCCH front = data + offset;
	int8_t behinds = 0;
	while (*front != 0x00)
	{
		if ((*front & 0xC0) == 0xC0)
		{
			// ƫ������β
			partial.append(findname(data, (*front & 0x3F)));
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
	if (!partial.empty())
		partial.pop_back();

	return partial;
}

/// <summary>
/// ����UDP����
/// </summary>
/// <param name="udp">��������UDP��</param>
/// <param name="ipv4">ԴIPv4��ַ</param>
/// <returns>�����������</returns>
DNSCom::message_t DNSCom::_analyze(const dns_t& udp, ipv4_t srcipv4)
{
	message_t msg;
	msg.type = message_t::type_t::RECV;
	msg.ipv4 = srcipv4;
	msg.header = udp.header;

	LPCCH front = udp.data;	// ǰ��ָ�루���ֽڴ���
	LPCCH rear = front;		// ����ָ�루���front�����ַ�������
	std::string name;		// Name�ֶ�
	int16_t type;			// Type�ֶ�
	int16_t cls;			// Class�ֶ�
	int32_t ttl;			// TTL
	int16_t length;			// Data Length�ֶΣ����Կ���ipv4��str����ȡ
	ipv4_t ipv4;			// ��TypeΪAģʽ����Ч
	std::string str;		// CNAME��...��ģʽ����Ч

	bool error = false;
	/* ��ȡQuestion��¼ */
	int8_t behinds = 0;
	for (int16_t cnt = 0; cnt < udp.header.qdcount; ++cnt)
	{
		name = findname(udp.data, front - udp.data);
		while (*front != 0x00)
		{
			if ((*front & 0xC0) == 0xC0)
			{
				// ƫ������β
				front += sizeof(int16_t);
				break;
			}
			else
			{
				// �����ַ�������¼
				front += (*front + 1);
			}
		}
		if (*front == 0x00)
			front++;

		if (front + 2 * sizeof(int16_t) - udp.data < DATA_MAXN)
		{
			// �¸��ֶ�ΪType��A��CNAME��MX...��
			type = *((int16_t*)front);	// 16λ
			front += sizeof(int16_t);

			cls = *((int16_t*)front);	// 16λ
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
		for (int cnt = 0; cnt < udp.header.ancount; ++cnt)
		{
			// �ݹ���ȡName�ֶ�
			name = findname(udp.data, *front);
			while (*front != 0x00)
			{
				if ((*front & 0xC0) == 0xC0)
				{
					// ƫ������β
					front += sizeof(int16_t);
					break;
				}
				else
				{
					// �����ַ�������¼
					front += (*front + 1);
				}
			}
			if (*front == 0x00)
				front++;

			type = *((int16_t*)front);	// Type
			front += sizeof(int16_t);	// 16λ

			cls = *((int16_t*)front);	// Class
			front += sizeof(int16_t);	// 16λ

			ttl = *((int32_t*)front);	// TTL
			front += sizeof(int32_t);	// 32λ

			length = *((int16_t*)front);	// Data Length
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

			case message_t::dns_t::CNAME:
				// �ݹ���ȡCNAME�ֶ�
				name = findname(udp.data, *front);
				while (*front != 0x00)
				{
					if ((*front & 0xC0) == 0xC0)
					{
						// ƫ������β
						front += sizeof(int16_t);
						break;
					}
					else
					{
						// �����ַ�������¼
						front += (*front + 1);
					}
				}
				if (*front == 0x00)
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
						str
					}
				);
			}
		}
	}

	return msg;
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
	// TODO �����ñ���
	// 
	return dns_t();
}
