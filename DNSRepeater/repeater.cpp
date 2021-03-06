#include "pch.h"
#include "repeater.h"

DNSRepeater::DNSRepeater(ipv4_t _local) :
	_success(true),
	_localDnsServer(_local),
	_resolvers(),
	_com(_local)
{
}

DNSRepeater::~DNSRepeater()
{
}

void DNSRepeater::Run()
{
	DNSCom::message_t msg;
	while (_success)
	{
		msg = _com.RecvFrom();
		switch (msg.type)
		{
		case DNSCom::message_t::type_t::RECV:
			break;
		default:
			break;
		}
	}
}

void DNSRepeater::Stop()
{
	_success = false;
}
