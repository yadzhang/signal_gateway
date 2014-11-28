#include "CRtcCallModule.h"

CLONE_COMP(CRtcCallModule)
CREATE_COMP(CRtcCallModule)

CRtcCallModule::CRtcCallModule(PCGFSM afsm) :CUACSTask(afsm),
	m_fsmContext(*this), m_isDispatcherAddrSet(FALSE), m_isReCall(false){
	// get LOGADDR_DISPATCHER from conf
	CProperties* properties = CPropertiesManager::getInstance()->getProperties("rtc.env");
	int LOGADDR_DISPATCHER = properties->getIntProperty("LOGADDR_DISPATCHER");
	if (LOGADDR_DISPATCHER == -1){
		print("LOGADDR_DISPATCHER not correctly set in samples.env,Use DEFAULT 231.\n");
		this->LOGADDR_DISPATCHER = 231;
	}
	else {
		this->LOGADDR_DISPATCHER = LOGADDR_DISPATCHER;
	}


	m_RtcCtrlMsg = new TRtcCtrlMsg();
	m_isReCall = false;
}

CRtcCallModule::~CRtcCallModule(){
	if(m_RtcCtrlMsg){
		delete m_RtcCtrlMsg;
		m_RtcCtrlMsg = NULL;
	}
}

PTUACData CRtcCallModule::createData(){
	return new TUACData();
}

void CRtcCallModule::initState(){
	m_fsmContext.enterStartState();
}

/** 在这里填充dispatcher的地址
 *  如果DIALOG_END，则通知dispatcher，消除会话信息
 *  如果消息最终发到sip（type = sip）那么需要进行转换再发到dispatcher，否则直接转发。见文档
 */
void CRtcCallModule::sendToDispatcher(TUniNetMsg *pMsg){
	// 也许该记录下dispatcher的地址
	if(m_isDispatcherAddrSet){
		pMsg->tAddr = m_dispatcherAddr;
	}else{
		pMsg->tAddr.phyAddr = 0;
		pMsg->tAddr.taskInstID = 0;
		pMsg->tAddr.logAddr = LOGADDR_DISPATCHER;
	}

	if(pMsg->dialogType == DIALOG_END){
		sendMsg(pMsg);
		return;
	}

	if(pMsg->msgType == RTC_TYPE){

		// just copy the message
		TUniNetMsg *pCopyMsg = (TUniNetMsg *)pMsg->cloneMsg();

		PTRtcCtrlMsg pCtrl = (PTRtcCtrlMsg)pCopyMsg->ctrlMsgHdr;
		printf("offersessionId %s\n", pCtrl->offerSessionId.c_str());
		sendMsg(pCopyMsg);

		return;
	}

	if(pMsg->msgType == SIP_TYPE){
		TUniNetMsg *pNewMsg = new TUniNetMsg();
		msgMap(pMsg, pNewMsg);
		sendMsg(pNewMsg);
	}

}

void CRtcCallModule::endTask(){
	printf("endTask current state: %s %d\n",m_fsmContext.getState().getName(),m_fsmContext.getState().getId());
	// 产生一条DIALOG——END消息，发给dispatcher，清除会话信息
	TUniNetMsg *pMsg = new TUniNetMsg();
	pMsg->dialogType = DIALOG_END;
	pMsg->msgType = RTC_TYPE;	// 无所谓，先判断dialogType
	pMsg->msgName = RTC_OK;
	pMsg->tAddr.logAddr = LOGADDR_DISPATCHER;
	pMsg->ctrlMsgHdr = m_RtcCtrlMsg->clone();
	pMsg->setCtrlMsgHdr();

	sendToDispatcher(pMsg);
	end();
	printf("endTask finish\n");
}

//处理消息
void CRtcCallModule::procMsg(PTUniNetMsg msg){
	if(!m_isDispatcherAddrSet){
		m_dispatcherAddr = msg->oAddr;
		m_isDispatcherAddrSet = TRUE;
	}
	printf("current state: %s %d\n",m_fsmContext.getState().getName(),m_fsmContext.getState().getId());
	printf("recv msg from %d, and msgName %s\n", msg->oAddr.logAddr, msg->getMsgNameStr());
	switch(msg->msgName){
	case RTC_OFFER:
		*m_RtcCtrlMsg = *((PTRtcCtrlMsg)msg->ctrlMsgHdr);
		m_caller = m_RtcCtrlMsg->from;
		m_callee = m_RtcCtrlMsg->to;
		m_offerSessionId = m_RtcCtrlMsg->offerSessionId;
		if(msg->msgType == SIP_TYPE){
			m_isCaller = true;
		}	
		else{
			m_isCaller = false;
		}
		printf("from: %s, to: %s\n", m_RtcCtrlMsg->from.c_str(), m_RtcCtrlMsg->to.c_str());
		m_seq = ((TRtcOffer *)msg->msgBody)->seq;
//		storeCallerOfferSessionIdPair(msg);
	case RTC_ANSWER:
	case RTC_INFO:
	case RTC_OK:
	case RTC_SHUTDOWN:
	case RTC_ERROR:
		m_fsmContext.onMessage(msg);
		break;
	default:
		printf("###CRtcCallModule:unknow msgName %s\n",msg->getMsgNameStr());
		//收到非法消息,忽略.等待超时.
		//endTask();
		break;
	}
	printf("after procMsg state: %s %d\n",m_fsmContext.getState().getName(),m_fsmContext.getState().getId());
}

//处理定时器超时
void CRtcCallModule::onTimeOut (TTimeMarkExt timerMark){
	sendBackError();
	print("The CRtcCallModule task received a timeout event: %d!!!\n", timerMark.timerId);
	errorLog("[CRtcCallModule]ERROR: The CRtcCallModule task received a timeout event: %d!!!\n", timerMark.timerId);
	m_fsmContext.onTimeOut(timerMark);
}

//
BOOL CRtcCallModule::msgMap(TUniNetMsg *pSrcMsg, TUniNetMsg *pDestMsg){
	return CRtcToSip::instance()->msgMap(pSrcMsg, pDestMsg, m_caller, m_isReCall);
}

void CRtcCallModule::sendBackError(){
	TUniNetMsg *pNewMsg = new TUniNetMsg();
	pNewMsg->dialogType = DIALOG_CONTINUE;
	pNewMsg->msgType = RTC_TYPE;
	pNewMsg->msgName = RTC_ERROR;
	//pNewMsg->tAddr = LOGADDR_DISPATCHER;
	TRtcCtrlMsg * pCtrl = new TRtcCtrlMsg();
	pCtrl->from = m_caller;
        pCtrl->to = m_callee;
	pCtrl->offerSessionId = m_offerSessionId;
	pCtrl->rtcType = ROAP_ERROR;
	if(m_isCaller){
		printf("from %s,to %s\n", pCtrl->from.c_str(), pCtrl->to.c_str());
		std::swap(pCtrl->from, pCtrl->to);
	}
	pCtrl->answerSessionId = "webrtc_4ff57274d9a89b47c415be9c1";
	pNewMsg->ctrlMsgHdr = pCtrl;
	pNewMsg->setCtrlMsgHdr();
	TRtcError * pError = new TRtcError();
	pError->seq = m_seq;
	pNewMsg->msgBody = pError;
	pError->errorType = ERROR_TIMEOUT;
	pNewMsg->setMsgBody();
	sendToDispatcher(pNewMsg);
	
}


void CRtcCallModule::sendBackOK(TUniNetMsg *msg){ 
	 TUniNetMsg *pNewMsg = new TUniNetMsg();
	 pNewMsg->dialogType = DIALOG_CONTINUE;
	 pNewMsg->msgType =	RTC_TYPE;
	 pNewMsg->msgName = RTC_OK;
	 pNewMsg->tAddr = msg->oAddr;

	 TRtcCtrlMsg *pCtrl = (TRtcCtrlMsg*)msg->cloneCtrlMsg();
	 std::swap(pCtrl->from, pCtrl->to);
	 pCtrl->rtcType=ROAP_OK;
	 pNewMsg->ctrlMsgHdr = pCtrl;
	 pNewMsg->setCtrlMsgHdr();

	 TRtcOK* pOk = new TRtcOK();
	 pOk->seq = ((TRtcShutdown*)msg->msgBody)->seq ;
	 pNewMsg->msgBody = pOk;
	 pNewMsg->setMsgBody();

	 sendToDispatcher(pNewMsg);
}
