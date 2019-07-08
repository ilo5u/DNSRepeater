#pragma once

#pragma warning(disable:4996)

//using namespace std;

typedef int32_t ipv4_t;





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
		int num;				//���
		ipv4_t ClientIp;		//�ͻ���IP��ַ
		std::string DomainName;	//��ѯ������
		std::string TimeStamp;	//ʱ������

		//�����Ǽ���2����

	};


public:
	/// <summary>
	/// ��������Ϣ���ݵ�����β��
	/// </summary>
	void Write_DebugMsg(DebugMsg DeMsg);


	/// <summary>
	/// д��ĳ��������Ϣ����־��
	/// �Ӷ�����ɾ��
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
	std::list<DebugMsg> dms;





	//int LogLevel;				//������Ϣ����
	//std::string SeverIP;		//������IP


};


