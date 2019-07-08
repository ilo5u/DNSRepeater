// DNSRepeater.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include "repeater.h"
#include <iostream>
#include <fstream>

using namespace std;

#define defaultNS "10.9.3.4"					//默认名字服务器
#define defaultInitFileName "dnsrelay.txt"		//默认配置文件
#define defaultTtlLen 3600						//默认TTL为1h，即3600s

int initSet(string fileName);

int main(int argc, char* argv[])
{
	//程序初始配置
	string initFileName;						//配置文件
	ipv4_t nameSever;							//外部dns服务器

	//3种命令行语法
	if (argc == 1)								//dnsrelay	
	{
		initFileName = defaultInitFileName;
		nameSever = inet_addr(defaultNS);
	}
	else if (argc == 3)							//dnsrelay -dd 202.99.96.68
	{
		initFileName = defaultInitFileName;
		nameSever = inet_addr(argv[2]);
	}
	else if (argc == 4)							//dnsrelay -d 192.168.0.1 c:\dns-table.txt
	{
		initFileName = argv[3];
		nameSever = inet_addr(argv[2]);
	}

	initSet(initFileName);						//将配置文件导入域名解析数据库
	DNSRepeater repeater(nameSever);

	//运行
	repeater.Run();

	return 0;
}

//将初始配置文件导入域名解析数据库
int initSet(string fileName)
{
	//先清空数据库
	DNSDBMS dbms;
	dbms.Connect();
	dbms.Clear();

	ifstream initFile(fileName.c_str(), ios::in);

	//文件打开失败
	if (!initFile)
	{
		cout << "配置文件打开失败！" << endl;
		return -1;
	}

	//文件打开成功
	else
	{
		while (!initFile.eof())
		{
			string IP, domain;
			initFile >> IP >> domain;
			if (IP != "" && domain != "")
			{
				//插入数据库(TTL默认缓存1h，即3600s；cls默认为In；type默认为A类型；preference只在MX模式有效，所以默认为0)
				dbms.Insert(domain, defaultTtlLen, (int)DNSCom::message_t::class_t::In, (int)DNSCom::message_t::dns_t::A, 0, std::to_string(inet_addr(IP.c_str())));
			}
		}
		initFile.close();
		cout << "配置文件导入成功！" << endl;
	}

	dbms.Disconnect();
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
