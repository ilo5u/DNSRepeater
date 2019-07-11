#pragma once

#pragma warning(disable:4996)

#include <fstream>

//using namespace std;

typedef uint32_t ipv4_t;

const int MAX_DOMAINNAME_NUM = 10;

/// <summary>
/// 写日志文件
/// 将调试信息输出至命令行
/// </summary>
class Log {

	/// <summary>
	/// 外部可见类型
	/// </summary>
public:
	/// <summary>
	/// 调试配置信息
	/// </summary>
	struct DebugConfig {
		int DebugLevel;			//调试信息级别
		ipv4_t NameSeverIP;		//名字服务器IP
	};

	/// <summary>
	/// 调试内容信息
	/// </summary>
	struct DebugMsg {

		//以下是级别1必须
		int id1 = 0;				//序号，接收时使用
		int id2 = 0;				//序号，发送时使用
		ipv4_t ClientIp = 0;		//客户端IP地址
		std::string DomainName[MAX_DOMAINNAME_NUM];	//查询的域名
		int DomainName_Num = 0;
		int Type = 0;
		std::string TimeStamp;	//时间坐标

		//以下是级别2附加

	};


public:
	/// <summary>
	/// 读调试信息内容到队列尾部
	/// </summary>
	void Write_DebugMsg(DebugMsg DeMsg);

public:
	/// <summary>
	///	写、打印配置信息
	/// </summary>
	void Generate_Config_Info();

	/// <summary>
	///	写、打印内容信息
	/// </summary>
	void Generate_Log_info();

	/// <summary>
	/// Log类相关
	/// </summary>
public:
	Log(DebugConfig config);
	~Log();
	//记得关闭文件

public:



private:
	DebugConfig debugconfig{ 0,0 };
	//DebugMsg debugmsg;
	std::queue<DebugMsg> dms;
	//std::list<DebugMsg>::iterator _dms;
	std::mutex dmsProtect;
	std::thread GenerateTask;
	std::ofstream DebugLog;
	HANDLE LogSignal;
	//int _LogUnFinish;
	//int LogLevel;				//调试信息级别
	//std::string SeverIP;		//服务器IP


};








