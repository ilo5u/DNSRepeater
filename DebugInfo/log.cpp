#include "stdafx.h"
#include"log.h"

/// <summary>
/// 初始化配置信息
/// </summary>
Log::Log(DebugConfig config)
{
	debugconfig.DebugLevel = config.DebugLevel;
	debugconfig.NameSeverIP = config.NameSeverIP;
	Generate_Config_Info();
}


Log::~Log()
{

}

/// <summary>
/// 读调试信息内容到队列尾部
/// </summary>
void Log::Write_DebugMsg(DebugMsg DeMsg)
{
	DeMsg.TimeStamp = GetTime();//加上时间戳
	this->dms.push_back(DeMsg);
}

/// <summary>
/// 写完某个调试信息的日志后
/// 从队列中删除
/// </summary>
void Log::Done_DebugMsg()
{
	this->dms.erase(dms.begin());
}

/// <summary>
///	写、打印配置信息
/// </summary>
void Log::Generate_Config_Info()
{

	std::ofstream DebugLog("dnsrelay.txt", std::ios::app);

	//dnsrelay 
	if (this->debugconfig.DebugLevel ==  1) {
		DebugLog << "dnsrelay" << std::endl;
		std::cout << "dnsrelay" << std::endl;
	}

	//dnsrelay -d dns-sever-ipaddr filename
	else if (this->debugconfig.DebugLevel == 4) {
		DebugLog << "dnsrelay -d " << Int_to_IP(this->debugconfig.NameSeverIP)
			<< "c:/dns-table.txt" << std::endl;
		std::cout << "dnsrelay -d " << Int_to_IP(this->debugconfig.NameSeverIP)
			<< "c:/dns-table.txt" << std::endl;
	}

	//dnsrelay -d dns-sever-ipaddr
	else if (this->debugconfig.DebugLevel == 3) {
		DebugLog << "dnsrelay -dd " << Int_to_IP(this->debugconfig.NameSeverIP)
			<< std::endl;
		std::cout << "dnsrelay -dd " << Int_to_IP(this->debugconfig.NameSeverIP)
			<< std::endl;
	}
	DebugLog.close();
}

/// <summary>
///	写、打印内容信息
/// </summary>
void Log::Generate_Log_info()
{
	std::ofstream DebugLog("dnsrelay.txt", std::ios::app);
	std::string Log_Input;

	//dnsrelay 
	if (this->debugconfig.DebugLevel == 0) {

	}

	//dnsrelay -d dns-sever-ipaddr filename
	else if (this->debugconfig.DebugLevel == 1) {
		//std::string Log_Input;

		Log_Input += dms.begin()->TimeStamp;
		Log_Input += "\n";
		Log_Input += "\t客户端IP：";
		Log_Input += Int_to_IP(dms.begin()->ClientIp);
		Log_Input += "\n";
		Log_Input += "\t域名：";
		Log_Input += dms.begin()->DomainName;
		Log_Input += "\n";
		Log_Input += "\t序号：";
		Log_Input += std::to_string(dms.begin()->num);
		//Log_Input += "时间坐标：";
		Log_Input += "\n";


	}

	//dnsrelay -d dns-sever-ipaddr
	else {
		//std::string Log_Input;

		Log_Input += dms.begin()->TimeStamp;
		Log_Input += "\n";
		Log_Input += "\t客户端IP：";
		Log_Input += Int_to_IP(dms.begin()->ClientIp);
		Log_Input += "\n";
		Log_Input += "\t域名：";
		Log_Input += dms.begin()->DomainName;
		Log_Input += "\n";
		Log_Input += "\t序号：";
		Log_Input += std::to_string(dms.begin()->num);
		//Log_Input += "时间坐标：";
		Log_Input += "\n";
	}





	DebugLog.close();
}




std::string GetTime() {
	/// <summary>
	/// 得到tm存储的时间
	/// <summary>
	time_t now = time(0);
	tm *time_ = NULL;
	time_ = localtime(&now);

	int year = 1900 + time_->tm_year;
	int mon = time_->tm_mon + 1;
	int day = time_->tm_mday;
	int hour = time_->tm_hour;
	int min = time_->tm_min;
	int sec = time_->tm_sec;

	std::string TimeNow;
	TimeNow += std::to_string(year);
	TimeNow += '/';
	TimeNow += std::to_string(mon);
	TimeNow += '/';
	TimeNow += std::to_string(day);
	TimeNow += ' ';
	TimeNow += std::to_string(hour);
	TimeNow += ':';
	TimeNow += std::to_string(min);
	TimeNow += ':';
	TimeNow += std::to_string(sec);

	return TimeNow;
}


std::string Int_to_IP(ipv4_t source)
{
	//std::string IPaddr;
	char IPtemp[20];
	sprintf(IPtemp, "%d.%d.%d.%d",
		(source & 0xff000000) >> 24,
		(source & 0x00ff0000) >> 16,
		(source & 0x0000ff00) >> 8,
		(source & 0x000000ff));

	return std::string(IPtemp);
}

