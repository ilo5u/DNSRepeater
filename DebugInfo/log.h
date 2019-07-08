#pragma once

#pragma warning(disable:4996)

//using namespace std;

typedef int32_t ipv4_t;





///	<summary>
/// 返回string表示的时间
///	</summary>
std::string GetTime();

///	<summary>
/// 返回string表示的时间
///	</summary>
std::string Int_to_IP(ipv4_t source);



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
		int num;				//序号
		ipv4_t ClientIp;		//客户端IP地址
		std::string DomainName;	//查询的域名
		std::string TimeStamp;	//时间坐标

		//以下是级别2附加

	};


public:
	/// <summary>
	/// 读调试信息内容到队列尾部
	/// </summary>
	void Write_DebugMsg(DebugMsg DeMsg);


	/// <summary>
	/// 写完某个调试信息的日志后
	/// 从队列中删除
	/// </summary>
	void Done_DebugMsg();


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
	std::list<DebugMsg> dms;





	//int LogLevel;				//调试信息级别
	//std::string SeverIP;		//服务器IP


};


