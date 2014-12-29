#include "CRtcStack.h"

//default PSAID
INT CRtcStack::m_PSAID = 18;
CRtcStack::CRtcStack(INT psaid){
	m_PSAID = psaid;
	LOGADDR_DISPATCHER = CPropertiesManager::getInstance()->getProperties("rtc.env")->getIntProperty("LOGADDR_DISPATCHER");
	
	if(LOGADDR_DISPATCHER == -1){
		psaErrorLog(m_PSAID,"ERROR(%s:%d): LOGADDR_DISPATCHER is not set in file rtc.env, use 231\n",__FILE__, __LINE__);
		LOGADDR_DISPATCHER = 231;
	}
	

	string tmp = CPropertiesManager::getInstance()->getProperties("gateway.env")->getProperty("RTC_DOMAIN");
	if(tmp == ""){
		tmp = "webrtcdomain.com";
	}
	
	strcpy(RTC_DOMAIN,tmp.c_str());

	tmp = CPropertiesManager::getInstance()->getProperties("gateway.env")->getProperty("realmAddr");
	if(tmp == ""){
		tmp = "open-ims.com";
	}
	strcpy(IMS_DOMAIN,tmp.c_str());

	tmp = CPropertiesManager::getInstance()->getProperties("gateway.env")->getProperty("confRealm");
	if(tmp == ""){
		tmp = "imsconf.com";
	}
	strcpy(CONF_DOMAIN,tmp.c_str());

	tmp = CPropertiesManager::getInstance()->getProperties("gateway.env")->getProperty("confType");
	if(tmp != ""){
		strcpy(CONF_TYPE,tmp.c_str());
	}


	m_pSocket = new CPracticalSocket();
}

CRtcStack::~CRtcStack(){
	delete m_pSocket;
	m_pSocket = NULL;
}

BOOL CRtcStack::init(int mediaPort, int wcsPort){
	return m_pSocket->init(mediaPort, wcsPort);
}

BOOL CRtcStack::convertMsgToUniNetMsg(string strMsg, PTUniNetMsg pMsg){
	try{
		CRtcProtocolParser rtcParser(strMsg);
		CRoapParser roapParser = rtcParser.getRoapParser();

		pMsg->msgType = RTC_TYPE;
		// always BEGIN ?
		pMsg->dialogType = DIALOG_BEGIN;
		pMsg->oAddr.logAddr = m_PSAID;
		pMsg->tAddr.logAddr = LOGADDR_DISPATCHER;

		// set ctrl msg
		PTRtcCtrlMsg pCtrlMsg = new TRtcCtrlMsg();
		pCtrlMsg->rtcType = rtcParser.getType();

		string fromStr = rtcParser.getFrom().c_str();
		int pos = fromStr.find("@");
		if(pos != string::npos){
			fromStr.replace(pos, 1, "~");	
		}
		fromStr.append("@"+(string)RTC_DOMAIN);
		

		string toStr = rtcParser.getTo().c_str();
		if(!isConfCall(toStr)){
			pos = toStr.find("@");
			if(pos == string::npos){
				toStr.append("@"+(string)IMS_DOMAIN);
			}
		}
		else{
			toStr.append("@"+(string)CONF_DOMAIN);
		}


		pCtrlMsg->from = fromStr.c_str();
		pCtrlMsg->to = toStr.c_str();
		pCtrlMsg->offerSessionId = roapParser.getOfferSessionId().c_str();
		pCtrlMsg->answerSessionId = roapParser.getAnswerSessionId().c_str();
		pMsg->ctrlMsgHdr = pCtrlMsg;
		pMsg->setCtrlMsgHdr();

		int roapType = roapParser.getType();
		if(roapType == ROAP_OFFER){
			pMsg->msgName = RTC_OFFER;
			PTRtcOffer pMsgBody = new TRtcOffer();
			pMsgBody->seq = roapParser.getSeq();
			pMsgBody->sdp = roapParser.getSdp().c_str();
			pMsgBody->tieBreaker = roapParser.getTieBreaker().c_str();
			pMsg->msgBody = pMsgBody;
			pMsg->setMsgBody();
		}else if(roapType == ROAP_ANSWER){
			pMsg->msgName = RTC_ANSWER;
			PTRtcAnswer pMsgBody = new TRtcAnswer();
			pMsgBody->seq = roapParser.getSeq();
			pMsgBody->sdp = roapParser.getSdp().c_str();
			pMsgBody->moreComing = roapParser.isMoreComing();
			pMsg->msgBody = pMsgBody;
			pMsg->setMsgBody();
		}else if(roapType == ROAP_OK){
			pMsg->msgName = RTC_OK;
			PTRtcOK pMsgBody = new TRtcOK();
			pMsgBody->seq = roapParser.getSeq();
			pMsgBody->sdp = roapParser.getSdp().c_str();	//OK sdp,  re-offer->answer->OK
			pMsg->msgBody = pMsgBody;
			pMsg->setMsgBody();
		}else if(roapType == ROAP_SHUTDOWN){
			pMsg->msgName = RTC_SHUTDOWN;
			PTRtcShutdown pMsgBody = new TRtcShutdown();
			pMsgBody->seq = roapParser.getSeq();
			pMsg->msgBody = pMsgBody;
			pMsg->setMsgBody();
		}else if(roapType == ROAP_ERROR){
			pMsg->msgName = RTC_ERROR;
			PTRtcError pMsgBody = new TRtcError();
			pMsgBody->errorType = roapParser.getErrorType();
			pMsgBody->seq = roapParser.getSeq();
			pMsg->msgBody = pMsgBody;
			pMsg->setMsgBody();
		}else if(roapType == ROAP_CANDIDATE){
			pMsg->msgName = RTC_CANDIDATE;
			PTRtcCandidate pMsgBody = new TRtcCandidate();
			pMsgBody->seq = roapParser.getSeq();
			pMsgBody->label = roapParser.getLabel();
			pMsgBody->sdp = roapParser.getSdp().c_str();
			pMsg->msgBody = pMsgBody;
			pMsg->setMsgBody();
		}else if(roapType == ROAP_MESSAGE){
			pMsg->msgName = RTC_IM;
			PTRtcMessage pMsgBody = new TRtcMessage();
			pMsgBody->seq = roapParser.getSeq();
			pMsgBody->msgSize = roapParser.getMsgSize();
			pMsgBody->msgContent = roapParser.getMsgContent().c_str();
			pMsg->msgBody = pMsgBody;
			pMsg->setMsgBody();
		}else{
			printf("unhandle roaptype %d", roapType);
			return false;
		}
	}catch(std::runtime_error & e){
		printf("catch exception: %s\n", e.what());
		psaErrorLog(m_PSAID, "catch exception: %s\n", e.what());
		return false;
	}
	return true;
}

BOOL CRtcStack::convertUniMsgToPlainMsg(PTUniNetMsg uniMsg, string& plainMsg){
	printf("CRtcStack recv msg");
	CRoapParser* roapParser = NULL;
	try{
		PTRtcCtrlMsg pCtrlMsg = (PTRtcCtrlMsg)uniMsg->ctrlMsgHdr;
		switch(uniMsg->msgName){
		case RTC_OFFER:{
			PTRtcOffer pMsgOffer = (PTRtcOffer)uniMsg->msgBody;
			roapParser = CRoapParser::createOffer(pCtrlMsg->offerSessionId.c_str(),
									pCtrlMsg->answerSessionId.c_str(),
									pMsgOffer->seq,
									pMsgOffer->sdp.c_str(),
									pMsgOffer->tieBreaker.c_str());
			break;
		}
		case RTC_ANSWER:{
			PTRtcAnswer pMsgAnswer = (PTRtcAnswer)uniMsg->msgBody;
			roapParser = CRoapParser::createAnswer(pCtrlMsg->offerSessionId.c_str(),
					pCtrlMsg->answerSessionId.c_str(),
					pMsgAnswer->seq,
					pMsgAnswer->sdp.c_str(),
					pMsgAnswer->moreComing);
			break;
		}
		case RTC_OK:{
			PTRtcOK pMsgOk = (PTRtcOK)uniMsg->msgBody;
			roapParser = CRoapParser::createOK(pCtrlMsg->offerSessionId.c_str(),
					pCtrlMsg->answerSessionId.c_str(),
					pMsgOk->seq, pMsgOk->sdp.c_str());
			break;
		}
		//case RTC_ERROR:
		//{
		//	PTRtcShutdown pMsgShutdown = (PTRtcShutdown)uniMsg->msgBody;
                //      roapParser = CRoapParser::createShutdown(pCtrlMsg->offerSessionId.c_str(),
                //                        pCtrlMsg->answerSessionId.c_str(),
                //                        pMsgShutdown->seq);
                //        break;
		//}

		case RTC_INFO:
		{
			PTRtcInfo pMsgInfo = (PTRtcInfo) uniMsg->msgBody;
			roapParser = CRoapParser::createInfo(pCtrlMsg->offerSessionId.c_str(), pCtrlMsg->answerSessionId.c_str(),
					pMsgInfo->seq, pMsgInfo->content_length, pMsgInfo->content.c_str());
			break;
		}

		case RTC_UPDATE:
		{
			PTRtcUpdate pMsgUpdate = (PTRtcUpdate) uniMsg->msgBody;
			roapParser = CRoapParser::createUpdate(pCtrlMsg->offerSessionId.c_str(), pCtrlMsg->answerSessionId.c_str(),
					pMsgUpdate->seq, pMsgUpdate->content_length, pMsgUpdate->content.c_str());
			break;
		}

		case RTC_SHUTDOWN:
		{
			PTRtcShutdown pMsgShutdown = (PTRtcShutdown)uniMsg->msgBody;
			roapParser = CRoapParser::createShutdown(pCtrlMsg->offerSessionId.c_str(),
					pCtrlMsg->answerSessionId.c_str(),
					pMsgShutdown->seq);
			break;
		}
		case RTC_ERROR:{
			PTRtcError pMsgError = (PTRtcError)uniMsg->msgBody;
			roapParser = CRoapParser::createError(pCtrlMsg->offerSessionId.c_str(),
					pCtrlMsg->answerSessionId.c_str(),
					pMsgError->seq,
					pMsgError->errorType);
			break;
		}
		case RTC_CANDIDATE:{
			PTRtcCandidate pMsgCand = (PTRtcCandidate)uniMsg->msgBody;
			roapParser = CRoapParser::createCandidate(pCtrlMsg->offerSessionId.c_str(),
					pCtrlMsg->answerSessionId.c_str(),
					pMsgCand->seq,
					pMsgCand->sdp.c_str(),
					pMsgCand->label);
			break;
		}
		case RTC_IM:{
			PTRtcMessage pMsgIM = (PTRtcMessage)uniMsg->msgBody;
			roapParser = CRoapParser::createMessage(pCtrlMsg->offerSessionId.c_str(),
					pCtrlMsg->answerSessionId.c_str(),
					pMsgIM->seq,
					pMsgIM->msgSize,
					pMsgIM->msgContent.c_str());
			break;
		}
		default:
			printf("can not convertUniMsgToPlainMsg msgName: %d\n", uniMsg->msgName);
			return FALSE;
		}

		string toStr = pCtrlMsg->to.c_str();

		int i = toStr.find("@");
		if(i != string::npos){
			toStr = toStr.substr(0,i);
			int pos = toStr.find("~");
			if(pos != string::npos){
				toStr.replace(pos,1, "@");
			}
		
		}

		string fromStr = pCtrlMsg->from.c_str();
		i = fromStr.find("@");

		if(i != string::npos){
			fromStr = fromStr.substr(0,i);
		}

		CRtcProtocolParser rtcParser(pCtrlMsg->rtcType,
				fromStr.c_str(),
				toStr.c_str(),
				*roapParser);
		plainMsg = rtcParser.toPlainString();
		delete roapParser;
		return TRUE;
	}catch(std::runtime_error& e){
		if(roapParser){
			delete roapParser;
			roapParser = NULL;
		}
		printf("catch exception: %s\n", e.what());
		psaErrorLog(m_PSAID, "catch exception: %s\n", e.what());
		return false;
	}
	return TRUE;
}

bool isMsgFromMediaGW(const string& domain){
	return MEDIA_GATEWAY_DOMAIN == domain;
}
// 有crypto字段表明加密，即WebRTC的，没有candidate
bool isSdpWithCandidate(const string& sdp){
	const string candidateFeature = "crypto";
       const string candidateFeature2 = "setup";
	//return sdp.find(candidateFeature) == string::npos;
		
        if((sdp.find(candidateFeature) == string::npos)&&(sdp.find(candidateFeature2) == string::npos))
	{				  
          return true;
	}				   	
	else	
	{
	return false;	
	}

//	return sdp.find(candidateFeature) == string::npos;
}
bool isOfferAnswerWithCandidate(PTUniNetMsg pMsg){
	if(pMsg->msgName == RTC_OFFER){
		TRtcOffer* pOffer = (TRtcOffer*)pMsg->msgBody;
		return isSdpWithCandidate(pOffer->sdp.c_str());
	}
	else{
		TRtcAnswer* pAnswer = (TRtcAnswer*)pMsg->msgBody;
		return isSdpWithCandidate(pAnswer->sdp.c_str());
	}
}
/*	psa接收到来自webrtc的消息只发送给媒体网关
 * （1）收到来自webrtc的非合成offer candidate
 * （2）收到来自webrtc的非合成answer candidate
 */
bool revedMsgOnlySendToMediaGW(const bool& isFromMg, PTUniNetMsg pMsg){
	if(!isFromMg){
		if(pMsg->msgName == RTC_CANDIDATE)
			return true;
		if(pMsg->msgName == RTC_OFFER)
			return !isOfferAnswerWithCandidate(pMsg);
		if(pMsg->msgName == RTC_ANSWER){
			TRtcAnswer* pRtcAnswer = (TRtcAnswer*) (pMsg->msgBody);
			if(pRtcAnswer->moreComing == 0){
				return !isOfferAnswerWithCandidate(pMsg);
			}
		}
	}
	return false;
}
/* psa接收到来自媒体网关的消息只发送给webrtc
 * （1）收到来自媒体网关的非合成answer candidate
 * （2）收到来自媒体网关的非合成offer candidate
 */
bool revedMsgOnlySendToWebRTCServer(const bool& isFromMg, PTUniNetMsg pMsg){
	if(isFromMg){
		if(pMsg->msgName == RTC_CANDIDATE)
			return true;
		if(pMsg->msgName == RTC_OFFER || pMsg->msgName == RTC_ANSWER)
			return !isOfferAnswerWithCandidate(pMsg);
	}
	return false;
}

/* psa接收到来自webrtc的消息同时发送给媒体网关和mcf内核
 * （1）收到来自webrtc server的shutdown
 */
bool revedMsgShouldSendToMediaGW(const bool& isFromMg, PTUniNetMsg pMsg){
	if(!isFromMg){
		if(pMsg->msgName == RTC_SHUTDOWN || pMsg->msgName == RTC_OK)
			return true;
	}
	return false;
}

/* 来自mcf内核的消息，发给媒体网关
 * （1）合成的answer，来自sip 200ok
 * （2）合成的offer，来自sip invite
 */
bool toSendOnlySendToMediaGW(PTUniNetMsg uniMsg){
	if(uniMsg->msgName == RTC_OFFER || uniMsg->msgName == RTC_ANSWER)
		return isOfferAnswerWithCandidate(uniMsg);
	if(uniMsg->msgName == RTC_INFO || uniMsg->msgName == RTC_UPDATE)
		return true;
	if(uniMsg->msgName == RTC_OK)
	{
		TRtcOK * rtcOk = (TRtcOK*) uniMsg->msgBody;
		if(rtcOk->sdp.length() == 0){
			printf("RTC OK sdp length == 0!!!\n");
			return true;
		}
	}

	return false;
}
/* 来自mcf内核的消息，同时发给媒体网关和webrtc server
 * （1）ims发起呼叫建立时的ok，来自sip ack
 * （2）ims挂掉的shutdown， 来自sip bye
 */
bool toSendShouldSendToMediaGW(PTUniNetMsg uniMsg){
	if(uniMsg->msgName == RTC_SHUTDOWN || uniMsg->msgName == RTC_OK || uniMsg->msgName == RTC_ERROR)
		return true;
	return false;
}

void CRtcStack::doActive(){
	int sockfd;	// 消息来自那个socket
	string plainMsg;
	if(m_pSocket->recvMsg(sockfd, plainMsg)){
		PTUniNetMsg pMsg = new TUniNetMsg();
		if(convertMsgToUniNetMsg(plainMsg, pMsg) ==  false){
			psaErrorLog(m_PSAID, "can not convertMsgToUniNetMsg: Msg: %s", plainMsg.c_str());
			return ;
		}

		bool isFromMg = m_pSocket->isFromMg(sockfd);
		printf("CRtcStack: recv msg from %d, and msgType %s\n", sockfd, pMsg->getMsgNameStr());

		TRtcCtrlMsg *pCtrl = (TRtcCtrlMsg *)pMsg->ctrlMsgHdr;
		string offersessionId(pCtrl->offerSessionId.c_str());

		if(pMsg->msgName == RTC_OFFER || pMsg->msgName == RTC_CANDIDATE){
			m_pSocket->insertNewMgMap(offersessionId);
		}


		bool isSendToMg = false; //msg need send to media gateway
	//	return;
		if(revedMsgOnlySendToMediaGW(isFromMg, pMsg)){
			printf("CRtcStack:doActive revedMsgOnlySendToMediaGW\n");
			isSendToMg = true;
			sendToWebRTCServerOrMediaGW(offersessionId, plainMsg, isSendToMg);
			return;
		}
		if(revedMsgOnlySendToWebRTCServer(isFromMg, pMsg)){	//
			printf("CRtcStack:doActive revedMsgOnlySendToWebRTCServer\n");
			isSendToMg = false;
			sendToWebRTCServerOrMediaGW(offersessionId, plainMsg, isSendToMg);
			return;
		}
		if(revedMsgShouldSendToMediaGW(isFromMg, pMsg)){ //shutdown
			printf("CRtcStack:doActive revedMsgShouldSendToMediaGW\n");
			isSendToMg = true;

			sendToWebRTCServerOrMediaGW(offersessionId, plainMsg, isSendToMg);

		}

		if(pMsg->msgName == RTC_SHUTDOWN || pMsg->msgName == RTC_ERROR){
			m_pSocket->deleteMgMap(offersessionId);
		}

		// 发送到mcf
		PTMsg mcfMsg = new TMsg();
		CMsgConvertor::convertMsg(pMsg, mcfMsg);
		sendMsgToPACM(mcfMsg);
	}
}

BOOL CRtcStack::doSendMsg(PTMsg pMsg){
	PTUniNetMsg uniMsg = (PTUniNetMsg) pMsg->pMsgPara;
	if(NULL == uniMsg){
		return FALSE;
	}
	
	bool isSendToMg = false; //msg need send to media gateway

	PTRtcCtrlMsg pCtrlMsg = (PTRtcCtrlMsg)uniMsg->ctrlMsgHdr;
	string plainMsg;
	if(uniMsg->msgName == RTC_ERROR)
	{
		CRoapParser * roapParser = NULL;
		PTRtcShutdown pMsgShutdown = (PTRtcShutdown)uniMsg->msgBody;
	        roapParser = CRoapParser::createShutdown(pCtrlMsg->offerSessionId.c_str(),
					                pCtrlMsg->answerSessionId.c_str(),
					                pMsgShutdown->seq);
		CRtcProtocolParser rtcParser(ROAP_SHUTDOWN,
                                pCtrlMsg->from.c_str(),
                                pCtrlMsg->to.c_str(),
                                *roapParser);
                plainMsg = rtcParser.toPlainString();
                delete roapParser;
	}
	else if(convertUniMsgToPlainMsg(uniMsg, plainMsg) == false){
		psaErrorLog(m_PSAID, "can not convertUniMsgToPlainMsg\n");
		return FALSE;
	}

	printf("plainMsg :: %s\n", plainMsg.c_str());

	TRtcCtrlMsg *pCtrl = (TRtcCtrlMsg *)uniMsg->ctrlMsgHdr;
	string offersessionId(pCtrl->offerSessionId.c_str());

	if(uniMsg->msgName == RTC_OFFER){
		m_pSocket->insertNewMgMap(offersessionId);
	}


	if(toSendOnlySendToMediaGW(uniMsg)){
		//from mcf, combine offer or answer with candidate
		printf("CRtcStack:doSendMsg toSendOnlySendToMediaGW\n");

		isSendToMg = true;
		sendToWebRTCServerOrMediaGW(offersessionId, plainMsg, isSendToMg);

		return TRUE;
	}

	if(toSendShouldSendToMediaGW(uniMsg)){
		//SHUTDOWN OK or ERROR
		printf("CRtcStack:doSendMsg toSendShouldSendToMediaGW\n");

		isSendToMg  = true;
		sendToWebRTCServerOrMediaGW(offersessionId, plainMsg, isSendToMg);
	}
	
	if(uniMsg->msgName == RTC_SHUTDOWN || uniMsg->msgName == RTC_ERROR){
		m_pSocket->deleteMgMap(offersessionId);
	}

	if(uniMsg->msgName == RTC_ERROR)
    {
        convertUniMsgToPlainMsg(uniMsg, plainMsg);
    }

	//the message need send to webrtc server
	isSendToMg = false;
	return sendToWebRTCServerOrMediaGW(offersessionId, plainMsg, isSendToMg);
}

BOOL CRtcStack::sendToWebRTCServerOrMediaGW(const string& offersessionId, const string& plainMsg, const bool isSendToMg){
	int clientSocket;

	if((clientSocket = m_pSocket->getClientSocketByDomain(offersessionId, isSendToMg)) == -1){
		psaErrorLog(m_PSAID, "can not get socketfd by domain %s!", offersessionId.c_str());
		return FALSE;
	}
	if(!m_pSocket->sendMsg(clientSocket, plainMsg, isSendToMg)){
		psaErrorLog(m_PSAID, "sendMsg to %d faild!", clientSocket);
		return FALSE;
	}
	return TRUE;
}

bool CRtcStack::isConfCall(string toStr)
{
	string confType = CONF_TYPE;
	if(confType == ""){
		return false;
	}
	printf("isConfCall: %s\n", confType.c_str());

	if(confType == "XXX" && toStr.size() == confType.size()){
		if(toStr.compare("000") >= 0
				&& toStr.compare("999") <= 0){
			return true;
		}
	}
	else if(confType == toStr){
		return true;
	}

	return false;
}

