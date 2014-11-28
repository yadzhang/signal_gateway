#include "pachook.h"
#include "infoext.h"
#include "CPsaRtc.h"
#include "dyncomploader.h"

static PCPsaRtc s_pRtc = NULL;

//initPsaTest的声明必须在宏INIT_PSA_COMP之前。
void initPsaRtc(int);
//这个宏是必须的。compLoader需要利用它来加载组件。
INIT_PSA_COMP(PsaRtc)

void hookActivePsaRtcImpl()
{
	 if (NULL != s_pRtc)
	 {
		 s_pRtc->doActive();
	 }
}

BOOL hookSendMsgPsaRtcImpl(PTMsg msg)
{
	if (NULL != s_pRtc)	{
		return s_pRtc->doSendMsg(msg);
	}else	{
		return FALSE;
	}

}

void initPsaRtc(int psaid){
	printf("initPsaRtc psaid: %d", psaid);
	setHookActive(psaid, hookActivePsaRtcImpl);
	setHookSendMsg(psaid, hookSendMsgPsaRtcImpl);

	s_pRtc = new CPsaRtc(psaid);
	if(s_pRtc->init()){
		printf("RTC PSA init successed\n");
	}else{
		psaErrorLogCS(psaid, "PSA init failed");
		delete s_pRtc;
		s_pRtc = NULL;
	}

}
