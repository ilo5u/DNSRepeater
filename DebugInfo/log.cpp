#include "stdafx.h"
#include "log.h"

/// <summary>
/// 初始化配置信息
/// </summary>
/// <param name="config">调试配置信息</param>
Log::Log(DebugConfig config)
{
	//初始化
	LogSignal = CreateSemaphore(NULL, 0x00, 0xff, NULL);
	//_LogUnFinish = 0;
	debugconfig.DebugLevel = config.DebugLevel;
	debugconfig.NameSeverIP = config.NameSeverIP;
	Generate_Config_Info();
	//std::thread GenerateTask(&Log::Generate_Log_info, this);

}

/// <summary>
/// 资源释放
/// </summary>
Log::~Log()
{
	if (GenerateTask.joinable()) {
		GenerateTask.join();
	}
}

/// <summary>
/// 读调试信息内容到队列尾部
/// </summary>
void Log::Write_DebugMsg(DebugMsg DeMsg)
{
	DeMsg.TimeStamp = GetTime();//加上时间戳
	dmsProtect.lock();

	this->dms.push(DeMsg);
	ReleaseSemaphore(LogSignal, 0x01, NULL);

	dmsProtect.unlock();
}

/// <summary>
/// 开启线程
/// </summary>
void Log::Done_DebugMsg()
{
	ReleaseSemaphore(LogSignal, 0x01, NULL);

	std::thread GenerateTask(&Log::Generate_Log_info, this);
	GenerateTask.join();
}

/// <summary>
///	写、打印配置信息
/// </summary>
void Log::Generate_Config_Info()
{

	std::ofstream DebugLog("dnslog.txt", std::ios::trunc);

	//dnsrelay 
	if (this->debugconfig.DebugLevel == 1) {
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
///	将完成的内容从队列中删除
/// </summary>
void Log::Generate_Log_info()
{
	std::ofstream DebugLog("dnslog.txt", std::ios::app);

	Log::DebugMsg msgTemp;
	std::string Log_Input = "";

	//_LogUnFinish++;

	while (!dms.empty()) {
		//_LogUnFinish--;
		WaitForSingleObject(LogSignal, 1000);

		dmsProtect.lock();

		msgTemp = dms.front();
		dms.pop();

		dmsProtect.unlock();

		Log_Input = "";

		//dnsrelay 
		if (this->debugconfig.DebugLevel == 1) {

		}

		//dnsrelay -d dns-sever-ipaddr filename
		else if (this->debugconfig.DebugLevel == 4) {
			//std::string Log_Input;

			Log_Input += msgTemp.TimeStamp;
			Log_Input += "\n";
			Log_Input += "\t客户端IP：";
			Log_Input += Int_to_IP(msgTemp.ClientIp);
			Log_Input += "\n";
			Log_Input += "\t域名：\t";
			for (int i = 0; i < msgTemp.DomainName_Num; i++) {
				Log_Input += msgTemp.DomainName[i];
				Log_Input += "\n\t\t";
			}
			Log_Input += "\n";
			Log_Input += "\t接收序号：";
			Log_Input += Tran_to_hex(msgTemp.id1);
			Log_Input += "\n";
			Log_Input += "\t变换后序号：";
			Log_Input += Tran_to_hex(msgTemp.id2);
			//Log_Input += "时间坐标：";
			Log_Input += "\n";


		}

		//dnsrelay -d dns-sever-ipaddr
		else {
			//std::string Log_Input;

			Log_Input += msgTemp.TimeStamp;
			Log_Input += "\n";
			Log_Input += "\t客户端IP：";
			Log_Input += Int_to_IP(msgTemp.ClientIp);
			Log_Input += "\n";
			Log_Input += "\t域名：\t";
			for (int i = 0; i < msgTemp.DomainName_Num; i++) {
				Log_Input += msgTemp.DomainName[i];
				Log_Input += "\n\t\t";
			}
			Log_Input += "\n";
			Log_Input += "\t接收序号：";
			Log_Input += Tran_to_hex(msgTemp.id1);
			Log_Input += "\n";
			Log_Input += "\t变换后序号：";
			Log_Input += Tran_to_hex(msgTemp.id2);
			Log_Input += "\n";
		}


		std::cout << Log_Input;
		DebugLog << Log_Input;

		//dmsProtect.unlock();




	}//end of while(true)


	DebugLog.close();
}


std::string Tran_to_hex(int n)
{
	char temp[10];
	std::string HEX = "";
	itoa(n, temp, 16);

	int tempLenth = strlen(temp);
	for (int i = 0; i < 4 - tempLenth; i++) {
		HEX += "0";
	}
	HEX += std::string(temp);

	return HEX;
}

///	<summary>
/// 返回string表示的时间
///	</summary>
std::string GetTime() {
	/// <summary>
	/// 得到tm存储的时间
	/// <summary>
	time_t now = time(0);
	tm* time_ = NULL;
	time_ = localtime(&now);

	int year = 1900 + time_->tm_year;
	int mon = time_->tm_mon + 1;
	int day = time_->tm_mday;
	int hour = time_->tm_hour;
	int min = time_->tm_min;
	int sec = time_->tm_sec;

	std::string TimeNow = "";
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

///	<summary>
/// 返回string表示的时间
///	</summary>
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
