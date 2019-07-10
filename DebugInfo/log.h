#pragma once

#pragma warning(disable:4996)

//using namespace std;

typedef int32_t ipv4_t;


const int MAX_DOMAINNAME_NUM = 10;



///	<summary>
/// ����string��ʾ��ʱ��
///	</summary>
std::string GetTime();

///	<summary>
/// ����string��ʾ��ʱ��
///	</summary>
std::string Int_to_IP(ipv4_t source);



/// <summary>
/// д��־�ļ�
/// ��������Ϣ�����������
/// </summary>
class Log {

	/// <summary>
	/// �ⲿ�ɼ�����
	/// </summary>
public:
	/// <summary>
	/// ����������Ϣ
	/// </summary>
	struct DebugConfig {
		int DebugLevel;			//������Ϣ����
		ipv4_t NameSeverIP;		//���ַ�����IP
	};


	/// <summary>
	/// ����������Ϣ
	/// </summary>
	struct DebugMsg {

		//�����Ǽ���1����
		int id1 = 0;				//��ţ�����ʱʹ��
		int id2 = 0;				//��ţ�����ʱʹ��
		ipv4_t ClientIp = 0;		//�ͻ���IP��ַ
		std::string DomainName[MAX_DOMAINNAME_NUM];	//��ѯ������
		int DomainName_Num = 0;
		std::string TimeStamp;	//ʱ������

		//�����Ǽ���2����

	};


public:
	/// <summary>
	/// ��������Ϣ���ݵ�����β��
	/// </summary>
	void Write_DebugMsg(DebugMsg DeMsg);


	/// <summary>
	/// �����߳�
	/// </summary>
	void Done_DebugMsg();


public:
	/// <summary>
	///	д����ӡ������Ϣ
	/// </summary>
	void Generate_Config_Info();


	/// <summary>
	///	д����ӡ������Ϣ
	/// </summary>
	void Generate_Log_info();


	/// <summary>
	/// Log�����
	/// </summary>
public:
	Log(DebugConfig config);
	~Log();
	//�ǵùر��ļ�

public:



private:
	DebugConfig debugconfig{ 0,0 };
	//DebugMsg debugmsg;
	std::queue<DebugMsg> dms;
	//std::list<DebugMsg>::iterator _dms;
	std::mutex dmsProtect;
	std::thread GenerateTask;
	HANDLE LogSignal;
	//int _LogUnFinish;
	//int LogLevel;				//������Ϣ����
	//std::string SeverIP;		//������IP


};








