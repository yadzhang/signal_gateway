#include "CSipCallModule.h"

CLONE_COMP(CSipCallModule)
CREATE_COMP(CSipCallModule)

CSipCallModule::CSipCallModule(PCGFSM afsm) :CUACSTask(afsm), m_fsmContext(*this){
	CProperties* properties = CPropertiesManager::getInstance()->getProperties("rtc.env");
	int LOGADDR_DISPATCHER = properties->getIntProperty("LOGADDR_DISPATCHER");
	if (LOGADDR_DISPATCHER == -1){
		print("LOGADDR_DISPATCHER not correctly set in samples.env,Use DEFAULT 231.\n");
		this->LOGADDR_DISPATCHER = 231;
	}
	else {
		this->LOGADDR_DISPATCHER = LOGADDR_DISPATCHER;
	}
	m_SipCtrlMsg = new TSipCtrlMsg();

	m_isReCall = false;
}

CSipCallModule::~CSipCallModule(){
	if(m_SipCtrlMsg){
		delete m_SipCtrlMsg;
		m_SipCtrlMsg = NULL;
	}
}

PTUACData CSipCallModule::createData(){
	return new TUACData();
}

void CSipCallModule::initState(){
	m_fsmContext.enterStartState();
}

bool CSipCallModule::isResp100_101(TUniNetMsg* msg)
{
	//如果该消息不是sip的response消息
	if(msg->msgType != SIP_TYPE && msg->msgName != SIP_RESPONSE)
		return false;

	//获得响应消息的状态码
	INT statusCode = ((PTSipResp)msg->msgBody)->statusCode;
	if(100 == statusCode || 101 == statusCode)
		return true;
	else
		return false;
}

bool CSipCallModule::isResp1xx(TUniNetMsg* msg)
{
	//如果该消息不是sip的response消息
	if(msg->msgType != SIP_TYPE && msg->msgName != SIP_RESPONSE)
		return false;

	//获得响应消息的状态码
	INT statusCode = ((PTSipResp)msg->msgBody)->statusCode;
	if(statusCode/100 == 1)
		return true;
	else
		return false;
}

bool CSipCallModule::isResp2xx(TUniNetMsg* msg)
{
	//如果该消息不是sip的response消息
	if(msg->msgType != SIP_TYPE && msg->msgName != SIP_RESPONSE)
		return false;

	if(((PTSipResp)msg->msgBody)->statusCode == 200)
		return true;
	else
		return false;
}

bool CSipCallModule::isResp3xx_6xx(TUniNetMsg* msg)
{
	//如果该消息不是sip的response消息
	if(msg->msgType != SIP_TYPE && msg->msgName != SIP_RESPONSE)
		return false;

	//获得响应消息的状态码
	INT statusCode = ((PTSipResp)msg->msgBody)->statusCode;
	if(statusCode < 700 && statusCode > 300)
		return true;
	else
		return false;
}

bool CSipCallModule::isConfReINVITE(TUniNetMsg *pMsg){
	if(pMsg->msgType != SIP_TYPE && pMsg->msgName != SIP_INVITE)
		return false;

	TSipInvite* pSipInvite = (TSipInvite*) (pMsg->msgBody);

	if(pSipInvite->body.content.length() == 0 && m_SipCtrlMsg->via.branch.size() > 0){
		//由会议服务器发出的Re-Invite，sdp为空，会议服务器发出的消息via的长度大于0
		m_isReCall = true;
		return true;
	}
	else{
		return false;
	}

}

/** 在这里填充dispatcher的地址
 *  如果DIALOG_END，则通知dispatcher，消除会话信息
 *  如果消息最终发到sip（type = sip）那么直接转发，否则需要进行转换再发到dispatcher。见文档
 */
void CSipCallModule::sendToDispatcher(TUniNetMsg *pMsg){
	// 也许该记录下dispatcher的地址
	pMsg->tAddr.phyAddr = 0;
	pMsg->tAddr.taskInstID = 0;
	pMsg->tAddr.logAddr = LOGADDR_DISPATCHER;
	if(pMsg->dialogType == DIALOG_END){
		sendMsg(pMsg);
		return;
	}

	if(pMsg->msgType == SIP_TYPE){
		// just copy the message
		TUniNetMsg *pCopyMsg = (TUniNetMsg *)pMsg->cloneMsg();
		printf("send to dispatcher\n");
		sendMsg(pCopyMsg);
		return;
	}

	if(pMsg->msgType == RTC_TYPE){
		TUniNetMsg *pNewMsg = new TUniNetMsg();
		printf("&&&&sendToDispatcher: %d\n", m_isReCall);
		msgMap(pMsg, pNewMsg);
		sendMsg(pNewMsg);
	}
}

/*
 * 结束状态机
 * 需要向Dispatcher模块发送信息,通知这个处理状态机实例的结束
 * 删除Dispatcher模块存储的会话状态信息
 */
void CSipCallModule::endTask(){
	// 产生一条DIALOG——END消息，发给dispatcher，清除会话信息
	TUniNetMsg *pMsg = new TUniNetMsg();
	pMsg->dialogType = DIALOG_END;
	pMsg->msgType = SIP_TYPE;	// 无所谓，先判断dialogType
	pMsg->msgName = SIP_RESPONSE;
	pMsg->ctrlMsgHdr = m_SipCtrlMsg->clone();
	pMsg->setCtrlMsgHdr();

	sendToDispatcher(pMsg);
	end();
	printf("endTask finish");
}
void CSipCallModule::handleTimeoutAtCallProcState(){
	if(m_SipCtrlMsg->via.branch.size() < 1)	// 对于webrtc发起的呼叫是没有via字段的
		generateCancel();
	else
		generateAndSendTimeOutMsg();
}
//产生超时消息，使用场景：sipCSipCallModule::发出invite，超时
void CSipCallModule::generateAndSendTimeOutMsg(){
	printf("CSipCallModule::generateAndSendTimeOutMsg\n");
	TUniNetMsg *pMsg = new TUniNetMsg();
	pMsg->dialogType = DIALOG_CONTINUE;
	pMsg->msgType = SIP_TYPE;
	pMsg->msgName = SIP_RESPONSE;

	PTSipResp response = new TSipResp();
	response->statusCode = 408;
	response->reason_phase = "Request Timeout";
	pMsg->msgBody = response;
	pMsg->setMsgBody();

	pMsg->ctrlMsgHdr = m_SipCtrlMsg->clone();
	pMsg->setCtrlMsgHdr();

	sendToDispatcher(pMsg);
}

BOOL CSipCallModule::msgMap(TUniNetMsg *pSrcMsg, TUniNetMsg *pDestMsg){
	CSipToRtc::instance()->msgMap(pSrcMsg, pDestMsg, m_caller,m_callerHost, m_isReCall);//change by guoxun
	return TRUE;
} 

//处理消息
void CSipCallModule::procMsg(PTUniNetMsg msg){
	printf("current state: %s %d\n",m_fsmContext.getState().getName(),m_fsmContext.getState().getId());
	printf("recv msg from %d, msgName is %s\n", msg->oAddr.logAddr, msg->getMsgNameStr());

	switch(msg->msgName){
	case SIP_INVITE:
		*m_SipCtrlMsg = *((PTSipCtrlMsg)msg->ctrlMsgHdr);
		m_caller = m_SipCtrlMsg->from.url.username;
		m_callerHost = m_SipCtrlMsg->from.url.host;//add by guoxun
		recordVia(msg);
		m_fsmContext.onInvite(msg);
		break;
	case SIP_RESPONSE:
		if(msg->msgType == SIP_TYPE)	// webrtc回的answer
			attachRecordedViaToMsg(msg);
		m_fsmContext.onResponse(msg);
		break;
	case SIP_ACK:
		printf("CSipCallModule: has got ack\n");
		m_fsmContext.onAck(msg);
		break;
	case SIP_CANCEL:
		m_fsmContext.onCancel(msg);
		break;
	case SIP_BYE:
		m_fsmContext.onBye(msg);
//		sendBack200OK(pCloneMsg);
		break;
	case SIP_INFO:
		m_fsmContext.onInfo(msg);
		break;
	default:
		printf("###CSipCallModule:unknow msgName %s\n",msg->getMsgNameStr());
		//收到非法消息,忽略.等待超时.
		//endTask();
		break;
 	}
	printf("after procMsg state: %s %d\n",m_fsmContext.getState().getName(),m_fsmContext.getState().getId());
//	delete pCloneMsg;
}

//处理定时器超时
void CSipCallModule::onTimeOut (TTimeMarkExt timerMark){
	print("The CSipCallModule task received a timeout event: %d!!!\n", timerMark.timerId);
	errorLog("[CSipCallModule]ERROR: The CSipCallModule task received a timeout event: %d!!!\n", timerMark.timerId);
	m_fsmContext.onTimeOut(timerMark);
 }

// add(1 function) by zhangyadong on 2014.7.14
void CSipCallModule::sendBackACK(TUniNetMsg *msg){
	printf("******send Back ACK\n");
	TUniNetMsg *pNewMsg = new TUniNetMsg();
	pNewMsg->dialogType = DIALOG_CONTINUE;
	pNewMsg->msgType = SIP_TYPE;
	pNewMsg->msgName = SIP_ACK;

	PTSipCtrlMsg pCtrlMsg = (PTSipCtrlMsg)msg->cloneCtrlMsg();
	pCtrlMsg->cseq_method = "ACK";
	pNewMsg->ctrlMsgHdr = pCtrlMsg;
	pNewMsg->setCtrlMsgHdr();
	printf("Middle");
	TSipReq * pSipReq = new TSipReq();
	pSipReq->req_uri = ((PTSipCtrlMsg)pNewMsg->ctrlMsgHdr)->to.url;
	pNewMsg->msgBody = pSipReq;
	pNewMsg->setMsgBody();

	sendToDispatcher(pNewMsg);
	printf("*******send Back ACK END\n");
}

void CSipCallModule::sendBackBYE(){
	printf("*******send back BYE\n");
	TUniNetMsg *pMsg = new TUniNetMsg();
	pMsg->dialogType = DIALOG_CONTINUE;
	pMsg->msgType = SIP_TYPE;
	pMsg->msgName = SIP_BYE;
	
	//TSipCtrlMsg *pSipCtrl = (TSipCtrlMsg *)m_SipCtrlMsg->clone();
	//if(m_SipCtrlMsg->via.branch.size() >= 1){
		//IMS主叫
	//	std::swap(pSipCtrl->from, pSipCtrl->to);
	//}	
	TSipCtrlMsg *pSipCtrl = new TSipCtrlMsg();

	if(m_SipCtrlMsg->via.branch.size() >= 1){
		pSipCtrl->from = m_SipCtrlMsg->to;
		pSipCtrl->to = m_SipCtrlMsg->from;
	}
	else{
		pSipCtrl->from = m_SipCtrlMsg->from;
		pSipCtrl->to = m_SipCtrlMsg->to;
	}



	pSipCtrl->cseq_method = "BYE";
	pMsg->ctrlMsgHdr = pSipCtrl;
	pMsg->setCtrlMsgHdr();

	TSipBye * pBye = new TSipBye();
	
	pBye->req_uri = pSipCtrl->to.url;

	pMsg->msgBody = pBye;
	pMsg->setMsgBody();

	sendToDispatcher(pMsg);

}

void CSipCallModule::sendBack200OK(TUniNetMsg *pCloneMsg){
	TUniNetMsg *pNewMsg = new TUniNetMsg();
	pNewMsg->dialogType = DIALOG_CONTINUE;
	pNewMsg->msgType = SIP_TYPE;
	pNewMsg->msgName = SIP_RESPONSE;
	pNewMsg->tAddr = pCloneMsg->oAddr;

	pNewMsg->ctrlMsgHdr = (PTSipCtrlMsg)pCloneMsg->cloneCtrlMsg();
	pNewMsg->setCtrlMsgHdr();

	TSipResp *pSipResp = new TSipResp();
	pSipResp->statusCode = 200;
	pSipResp->reason_phase = "ok";
	pNewMsg->msgBody = pSipResp;
	pNewMsg->setMsgBody();
	CTUniNetMsgHelper::print(pNewMsg);

	sendToDispatcher(pNewMsg);
}

 void CSipCallModule::sendBack488NotAcceptableHere(PTUniNetMsg msg){
	 TUniNetMsg *pNewMsg = new TUniNetMsg();
	 pNewMsg->dialogType = DIALOG_CONTINUE;
	 pNewMsg->msgType = SIP_TYPE;
	 pNewMsg->msgName = SIP_RESPONSE;
	 pNewMsg->tAddr = msg->oAddr;

	 pNewMsg->ctrlMsgHdr = (PTSipCtrlMsg)msg->cloneCtrlMsg();
	 pNewMsg->setCtrlMsgHdr();

	 TSipResp *pSipResp = new TSipResp();
	 pSipResp->statusCode = 488;
	 pSipResp->reason_phase = "Not Acceptable Here";
	 pNewMsg->msgBody = pSipResp;
	 pNewMsg->setMsgBody();

	 sendToDispatcher(pNewMsg);
 }

 void CSipCallModule::generateCancel(){
	 	printf("CSipCallModule::generateCancel\n");
		TUniNetMsg *pMsg = new TUniNetMsg();
		pMsg->dialogType = DIALOG_CONTINUE;
		pMsg->msgType = SIP_TYPE;
		pMsg->msgName = SIP_CANCEL;

		TSipCtrlMsg *pSipCtrl = (TSipCtrlMsg *)m_SipCtrlMsg->clone();
		pSipCtrl->cseq_method = "CANCEL";
		pMsg->ctrlMsgHdr = pSipCtrl;
		pMsg->setCtrlMsgHdr();


		TSipCancel *pCancel = new TSipCancel();
		pCancel->req_uri = pSipCtrl->from.url;
		pMsg->msgBody = pCancel;
		pMsg->setMsgBody();

		sendToDispatcher(pMsg);
 }

void CSipCallModule::recordVia(PTUniNetMsg msg){
	TSipCtrlMsg* psipCtrl = (TSipCtrlMsg*)msg->ctrlMsgHdr;
	m_sipvia = psipCtrl->via;
}

void CSipCallModule::attachRecordedViaToMsg(PTUniNetMsg msg){
	printf("XXXXXXXXXX\nCSipCallModule::attachRecordedViaToMsg\n");
	TSipCtrlMsg* psipCtrl = (TSipCtrlMsg*)msg->ctrlMsgHdr;
	psipCtrl->via = m_sipvia;
	msg->setCtrlMsgHdr();
}
