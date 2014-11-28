#include "CPsaRtc.h"

static PCRtcStack s_pStack;
CPsaRtc::CPsaRtc(INT psaid):m_psaid(psaid){

}

CPsaRtc::~CPsaRtc(){
	delete s_pStack;
	s_pStack = NULL;
}

BOOL CPsaRtc::init(){
	s_pStack = new CRtcStack(m_psaid);
	// should get port from config
    INT MEDIA_PORT = CPropertiesManager::getInstance()->getProperties("rtc.env")->getIntProperty("MEDIA_PORT");
    INT WCS_PORT = CPropertiesManager::getInstance()->getProperties("rtc.env")->getIntProperty("WCS_PORT");
	//INT port = 9870;
	if(s_pStack != NULL){
		return s_pStack->init(MEDIA_PORT, WCS_PORT);
	}else{
		return FALSE;
	}
}

void CPsaRtc::doActive(){
	if(s_pStack != NULL){
		s_pStack->doActive();
	}
}

BOOL CPsaRtc::doSendMsg(PTMsg msg){
	if(s_pStack != NULL){
		return s_pStack->doSendMsg(msg);
	}else{
		return false;
	}
}
