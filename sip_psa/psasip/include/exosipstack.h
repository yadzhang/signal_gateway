/************************************************************************

 * Copyright (c)2010-2012, by BUPT
 * All rights reserved.

 * FileName：       exosipstack.h
 * System：         MCF
 * SubSystem：      PSA
 * Author：         Huang Haiping
 * Date：           2010.04.07
 * Version：        1.0
 * Description：
        控制eXosip2协议栈

 *
 * Last Modified:
	  2010.04.07, 完成初始版本定义
		 By Huang Haiping


*************************************************************************/

#ifndef _EXOSIPSTACK_H
#define _EXOSIPSTACK_H

#include <eXosip2/eXosip.h>
#include <osip2/osip_mt.h>
#include <osipparser2/headers/osip_www_authenticate.h>
#include <netinet/in.h>
#include <vector>
#include <map>

#include "MD5Digest.h"
#include "CPropertiesManager.h"

#include "comtypedef.h"
#include "pachook.h"
#include "unihashtable.h"
#include "exosiptranslator.h"
#include "timerpoll.h"

typedef struct{
	string username;
	int reg_id;
	string cnonce;
	int noncecount;
} UserData;

_CLASSDEF(CExosipStack)
class CExosipStack {
public:
	CExosipStack(INT psaid);

	// INTERFACE
public:
	BOOL init(USHORT port);
	void doActive();
	BOOL doSendMsg(PTMsg msg);
	// INTERFACE END

private:
	INT m_psaid;
	CHashTable<CHAR*, INT> m_map_branch_tid; // Transaction map
	CHashTable<CHAR*, INT> m_map_callid; // call id map
	CHashTable<CHAR*, INT> m_map_dialogid; // dialog id map

	vector<string> m_name_pool;
	map<string, timer *> m_map_timers;
	map<string, vector<char *> > m_service_route;

	map<string, UserData *> m_map_userdata;  //save for heartbeat

	timers_poll * ptimer_poll;
	pthread_t thread_id;

	int accessMode;
	string confType;
	string confServer;

private:
	static void * thread_fun(void * data);
	static int sendInitRegister(timer *ptimer);
	static int sendAuthRegister(timer *ptimer);

	void register_process_401(eXosip_event_t * je);
	void register_process_200(eXosip_event_t * je);
	char * remove_quotes(char * text);
	char * add_quotes(string text);

	string generateRand();

	bool isConfCall(string username);

private:
	/* Id mapping function */
	void storeDid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId, INT dialogId);
	void storeCid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId, INT cid);

	void removeDid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId);
	void removeCid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId);

	/* -1 means not exist */
	INT getDid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId);
	INT getCid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId);

	/* Message handlers */
private:
	BOOL onSend_SIP_INVITE(PCTUniNetMsg uniMsg);
	BOOL onSend_SIP_REGISTER(PCTUniNetMsg uniMsg);
	BOOL onSend_SIP_MESSAGE(PCTUniNetMsg uniMsg);
	BOOL onSend_SIP_CANCEL(PCTUniNetMsg uniMsg);
	BOOL onSend_SIP_RESPONSE(PCTUniNetMsg uniMsg);
	BOOL onSend_SIP_ACK(PCTUniNetMsg uniMsg);
	BOOL onSend_SIP_BYE(PCTUniNetMsg uniMsg);
};

#endif /* _EXOSIPSTACK_H */
