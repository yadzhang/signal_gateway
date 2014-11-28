#ifndef _RTC_STACK_H_
#define _RTC_STACK_H_
#include "pachook.h"
//#include "infoext.h"
#include "CPropertiesManager.h"
#include "msgconvertor.h"
#include "CPracticalSocket.h"
#include "CRtcProtocolParser.h"
#include "dbHandler.h"
#include "rtc_msg_def.h"
#include "stdio.h"
#include <string>
#include <vector>
using namespace std;
const string MEDIA_GATEWAY_DOMAIN = "MEDIA_GATEWAY";

_CLASSDEF(CRtcStack)
class CRtcStack{
public:
	CRtcStack(INT psaid);
	virtual ~CRtcStack();

	// INTERFACE
	BOOL init(int, int);
	void doActive();
	BOOL doSendMsg(PTMsg pMsg);
	// INTERFACE END

	static INT m_PSAID;
private:
	CPracticalSocket* m_pSocket;
	BOOL convertMsgToUniNetMsg(string strMsg, PTUniNetMsg pMsg);
	BOOL convertUniMsgToPlainMsg(PTUniNetMsg uniMsg, string& plainMsg);
	INT LOGADDR_DISPATCHER;
	char RTC_DOMAIN[128];
	BOOL sendToWebRTCServerOrMediaGW(const string& key, const string& msg, const bool isSendToMg);
};

#endif
