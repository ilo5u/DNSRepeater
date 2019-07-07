#include "stdafx.h"
#include "dbms.h"

DNSDBMS::DNSDBMS() :
	_env(NULL), _con(NULL)
{
}

DNSDBMS::~DNSDBMS()
{
	Disconnect();
}

bool DNSDBMS::Connect()														//��ODBC����Դ����
{
	SQLRETURN ret = SQLAllocEnv(&_env);										//��ʼ��ODBC����
	if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
	{
		ret = SQLAllocConnect(_env, &_con);									//�������Ӿ��
		if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
		{
			SQLCHAR dataSource[] = "DNSDB";									//����Դ
			SQLCHAR username[] = "sa";										//�û���
			SQLCHAR password[] = "wbj321...";								//����
			ret = SQLConnect(
				_con,
				dataSource,
				SQL_NTS,
				username,
				SQL_NTS,
				password,
				SQL_NTS
			);

			if (ret = SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
			{
				return true;
			}
			SQLFreeConnect(_con);
		}
		SQLFreeEnv(_env);
	}
	return false;
}

void DNSDBMS::Disconnect()
{
	if (_con != NULL)
	{
		SQLDisconnect(_con);
		SQLFreeConnect(_con);
		_con = NULL;
	}
	if (_env != NULL)
	{
		SQLFreeEnv(_env);
		_env = NULL;
	}
}

struct record_t
{
	SQLVARCHAR dnsname[260];
	SQLINTEGER ttl;
	SQLINTEGER dnsclass;
	SQLINTEGER dnstype;
	SQLINTEGER preference;
	SQLVARCHAR dnsvalue[100];
};

//��ѯ����
DNSDBMS::results DNSDBMS::Select(DNSDBMS::search_t question)
{
	record_t rec;
	std::strcpy((char*)rec.dnsname, question.name.c_str());
	rec.dnsclass = question.cls;
	rec.dnstype = question.dnstype;

	char sql[0xFF];
	SQLHSTMT stm;															//�����
	results answers;														//���صĲ�ѯ���

	if (question.dnstype == 1)												//A������Ҫ�����ݿ���A���ͺ�CNAME���͵����ݶ�����
	{
		std::sprintf(sql,
			"select TTL, preference, dnsvalue from DNS where dnsname=%s and dnsclass=%d and (dnstype=%d or dnstype=%d)",
			rec.dnsname,
			rec.dnsclass,
			rec.dnstype,
			5);
	}
	else
	{
		std::sprintf(sql,
			"select TTL, preference, dnsvalue from DNS where dnsname=%s and dnsclass=%d and dnstype=%d",
			rec.dnsname,
			rec.dnsclass,
			rec.dnstype);
	}

	SQLRETURN ret = SQLAllocStmt(_con, &stm);								//Ϊ����������ڴ�
	//�����ݻ����������ݿ��е���Ӧ�ֶ�(�ڶ������������к�)
	ret = SQLBindCol(stm, 1, SQL_INTEGER, &rec.ttl, 0, 0);					//��������������������BufferLength���ٶ��������㹻���Ա�������
	ret = SQLBindCol(stm, 2, SQL_INTEGER, &rec.preference, 0, 0);
	ret = SQLBindCol(stm, 3, SQL_C_CHAR, rec.dnsvalue, _countof(rec.dnsvalue), 0);

	//�����������Ӧ������
	while (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
	{
		ret = SQLFetch(stm);
		if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
		{
			answers.push_back(
				{ 
					(char*)rec.dnsname,
					rec.dnstype, 
					rec.dnsclass, 
					rec.ttl, 
					rec.preference, 
					(char*)rec.dnsvalue 
				}
			);
		}
	}
	ret = SQLFreeStmt(stm, SQL_DROP);

	return answers;
}

//���뺯��
void DNSDBMS::Insert(std::string name, int ttl, int cls, int type, int preference, std::string value)
{
	record_t rec;
	std::strcpy((char*)rec.dnsname, name.c_str());
	rec.ttl = ttl;
	rec.dnsclass = cls;
	rec.dnstype = type;
	rec.preference = preference;
	std::strcpy((char*)rec.dnsvalue, value.c_str());

	SQLCHAR sql[0xFF];
	SQLHSTMT stm;															//�����
	std::sprintf((char*)(sql),
		"insert into DNS values(%s, %d, %d, %d, %d, %s)",
		rec.dnsname,
		rec.ttl,
		rec.dnsclass,
		rec.dnstype,
		rec.preference,
		rec.dnsvalue);

	SQLRETURN ret = SQLAllocStmt(_con, &stm);								//Ϊ����������ڴ�
	ret = SQLExecDirect(stm, sql, SQL_NTS);
	ret = SQLFreeStmt(stm, SQL_DROP);
}

//������ݿ⺯��
void DNSDBMS::Clear()
{
	SQLCHAR sql[0xFF] = "delete from DNS";
	SQLHSTMT stm;

	SQLRETURN ret = SQLAllocStmt(_con, &stm);								//Ϊ����������ڴ�
	ret = SQLExecDirect(stm, sql, SQL_NTS);
	ret = SQLFreeStmt(stm, SQL_DROP);
}

//ɾ��һ����¼
int DNSDBMS::DeleteRecod(result_t answer)
{
	record_t rec;
	std::strcpy((char*)rec.dnsname, answer.name.c_str());
	rec.dnsclass = answer.cls;
	rec.dnstype = answer.cls;
	rec.preference = answer.preference;
	rec.ttl = answer.ttl;
	std::strcpy((char*)rec.dnsvalue, answer.str.c_str());

	SQLCHAR sql[0xFF];
	SQLHSTMT stm;

	if (answer.dnstype == 0x000f)					//MX����
	{
		std::sprintf((char*)sql,
			"delete from DNS where dnsname=%s and dnsclass=%d and dnstype=%d and preference=%d and dnsvalue=%s",
			rec.dnsname,
			rec.dnsclass,
			rec.dnstype,
			rec.preference,
			rec.dnsvalue);
	}
	else
	{
		std::sprintf((char*)sql,
			"delete from DNS where dnsname=%s and dnsclass=%d and dnstype=%d and dnsvalue=%s",
			rec.dnsname,
			rec.dnsclass,
			rec.dnstype,
			rec.dnsvalue);
	}

	SQLRETURN ret = SQLAllocStmt(_con, &stm);								//Ϊ����������ڴ�
	ret = SQLExecDirect(stm, sql, SQL_NTS);
	ret = SQLFreeStmt(stm, SQL_DROP);

	return 1;
}

