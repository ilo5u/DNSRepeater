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

bool DNSDBMS::Connect()														//与ODBC数据源连接
{
	SQLRETURN ret = SQLAllocEnv(&_env);										//初始化ODBC环境
	if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
	{
		ret = SQLAllocConnect(_env, &_con);									//分配连接句柄
		if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
		{
			SQLCHAR dataSource[] = "DNSDB";									//数据源
			SQLCHAR username[] = "sa";										//用户名
			SQLCHAR password[] = "19981031";								//密码
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

//数据库记录，用于导入导出
struct record_t
{
	SQLVARCHAR dnsname[NAME_LEN];
	SQLINTEGER ttl;
	SQLINTEGER dnsclass;
	SQLINTEGER dnstype;
	SQLINTEGER preference;
	SQLVARCHAR dnsvalue[VALUE_LEN];
};

//查询函数
DNSDBMS::results DNSDBMS::Select(DNSDBMS::search_t question)
{
	record_t rec;
	std::strcpy((char*)rec.dnsname, question.name.c_str());
	rec.dnsclass = question.cls;
	rec.dnstype = question.dnstype;

	char sql[0xFF];
	SQLHSTMT stm;															//语句句柄
	results answers;														//返回的查询结果

	switch (rec.dnstype)
	{
	case (int)type_t::A:													//A类型需要将数据库中A类型和CNAME类型的数据都返回
		std::sprintf(sql,
			"select TTL, preference, dnsvalue, dnstype from DNS where dnsname='%s' and dnsclass=%d and (dnstype=%d or dnstype=%d)",
			rec.dnsname,
			rec.dnsclass,
			rec.dnstype,
			int(type_t::CNAME));
		break;
	default:
		std::sprintf(sql,
			"select TTL, preference, dnsvalue, dnstype from DNS where dnsname='%s' and dnsclass=%d and dnstype=%d",
			rec.dnsname,
			rec.dnsclass,
			rec.dnstype);
		break;
	}

	SQLRETURN ret = SQLAllocStmt(_con, &stm);								//为语句句柄分配内存
	ret = SQLExecDirect(stm, (SQLCHAR*)sql, SQL_NTS);

	//将数据缓冲区绑定数据库中的相应字段(第二个参数代表列号)
	ret = SQLBindCol(stm, 1, SQL_C_SLONG, &rec.ttl, 0, 0);					//对整数，驱动程序会忽略BufferLength并假定缓冲区足够大以保存数据
	ret = SQLBindCol(stm, 2, SQL_C_SLONG, &rec.preference, 0, 0);
	ret = SQLBindCol(stm, 3, SQL_C_CHAR, rec.dnsvalue, _countof(rec.dnsvalue), 0);
	ret = SQLBindCol(stm, 4, SQL_INTEGER, &rec.dnstype, 0, 0);

	bool hasCname = false;

	//遍历结果到相应缓冲区
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

			if (rec.dnstype == int(type_t::CNAME))
			{
				hasCname = true;
			}
		}
	}

	if (hasCname == true)													//查询结果包含CNAME，则需要一直继续查询直到查到ip
	{
		for (results::iterator aIter = answers.begin(); aIter != answers.end(); ++aIter)
		{
			if (aIter->dnstype == (int)type_t::CNAME)
			{
				char querySql[0xFF];
				std::sprintf(querySql,
					"select TTL, preference, dnsvalue, dnstype from DNS where dnsname='%s' and dnsclass=%d and dnstype=%d",
					aIter->name.c_str(),
					aIter->cls,
					aIter->dnstype);

				ret = SQLExecDirect(stm, (SQLCHAR*)querySql, SQL_NTS);

				ret = SQLBindCol(stm, 1, SQL_INTEGER, &rec.ttl, 0, 0);					
				ret = SQLBindCol(stm, 2, SQL_INTEGER, &rec.preference, 0, 0);
				ret = SQLBindCol(stm, 3, SQL_C_CHAR, rec.dnsvalue, _countof(rec.dnsvalue), 0);
				ret = SQLBindCol(stm, 4, SQL_INTEGER, &rec.dnstype, 0, 0);

				//遍历结果到相应缓冲区
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
			}
		}
	}

	ret = SQLFreeStmt(stm, SQL_DROP);

	return answers;
}

//插入函数
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
	SQLHSTMT stm;															//语句句柄
	std::sprintf((char*)(sql),
		"insert into DNS values('%s', %d, %d, %d, %d, '%s')",
		rec.dnsname,
		rec.ttl,
		rec.dnsclass,
		rec.dnstype,
		rec.preference,
		rec.dnsvalue);

	SQLRETURN ret = SQLAllocStmt(_con, &stm);								//为语句句柄分配内存
	if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
	{
		ret = SQLExecDirect(stm, sql, SQL_NTS);
		if (ret == SQL_SUCCESS || ret == SQL_SUCCESS_WITH_INFO)
		{
			//std::cout << "插入成功" << std::endl;
		}
		else
		{
			//std::cout << "插入失败" << std::endl;
		}
	}
	ret = SQLFreeStmt(stm, SQL_DROP);
}

//清空数据库函数
void DNSDBMS::Clear()
{
	SQLCHAR sql[0xFF] = "delete from DNS";
	SQLHSTMT stm;

	SQLRETURN ret = SQLAllocStmt(_con, &stm);								//为语句句柄分配内存
	ret = SQLExecDirect(stm, sql, SQL_NTS);
	ret = SQLFreeStmt(stm, SQL_DROP);
}

//删除一条记录(查询条件忽略TTL)
int DNSDBMS::DeleteRecod(result_t answer)
{
	record_t rec;
	std::strcpy((char*)rec.dnsname, answer.name.c_str());
	rec.dnsclass = answer.cls;
	rec.dnstype = answer.dnstype;
	rec.preference = answer.preference;
	rec.ttl = answer.ttl;
	std::strcpy((char*)rec.dnsvalue, answer.str.c_str());

	SQLCHAR sql[0xFF];
	SQLHSTMT stm;

	switch (rec.dnstype)
	{
	case (int)type_t::MX:													//MX类型
		std::sprintf((char*)sql,
			"delete from DNS where dnsname='%s' and dnsclass=%d and dnstype=%d and preference=%d and dnsvalue='%s'",
			rec.dnsname,
			rec.dnsclass,
			rec.dnstype,
			rec.preference,
			rec.dnsvalue);
		break;
	default:
		std::sprintf((char*)sql,
			"delete from DNS where dnsname='%s' and dnsclass=%d and dnstype=%d and dnsvalue='%s'",
			rec.dnsname,
			rec.dnsclass,
			rec.dnstype,
			rec.dnsvalue);
		break;
	}

	SQLRETURN ret = SQLAllocStmt(_con, &stm);								//为语句句柄分配内存
	ret = SQLExecDirect(stm, sql, SQL_NTS);
	ret = SQLFreeStmt(stm, SQL_DROP);

	return 1;
}

