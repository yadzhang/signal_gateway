/************************************************************************

 * Copyright (c)2010-2012, by BUPT
 * All rights reserved.

 * FileName：       exosipstack.C
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
	2010.07.20, fix sent out SIP message without route
		By Li Ling
	2010.09.09, fix several bug when building SIP message failed
		By Huang Haiping
	2010.09.15, fix not answering 200OK insubscription message
		By Huang Haiping

*************************************************************************/
#include "exosipstack.h"
#include "pachook.h"
#include "msgconvertor.h"
#include "psa_sip_inf.h"
#include "sipenv.h"
#include "CSipUserManager.h"
#include "CTUniNetMsgHelper.h"
#include <stdio.h>
#include <sstream>
#include <time.h>

set<string> m_name_pool;
map<string, timer *> m_map_timers;
map<string, UserData *> m_map_userdata;  //save for heartbeat

timers_poll * ptimer_poll;


string proxy, icscf, _realmAddr, realmAddr;
//int count = 0;
static CHAR* __generateUniqueCallId(CHAR* dst, size_t size,
		RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId)
{
	// <from-sipuri><to-sipuri><callid>
	strncat(dst, CSipMsgHelper::toString(from.url).c_str(), size);
	strncat(dst, CSipMsgHelper::toString(to.url).c_str(), size);
	strncat(dst, CSipMsgHelper::toString(callId).c_str(), size);

	return dst;
}

static CHAR* __generateUniqueDialogId(CHAR* dst, size_t size,
		RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId)
{
	// <from-tag><to-tag><callid>
//	strncat(dst, from.tag.c_str(), size);
//	strncat(dst, to.tag.c_str(), size);
//	strncat(dst, CSipMsgHelper::toString(callId).c_str(), size);
	strncat(dst, from.url.username.c_str(),size);
	strncat(dst, to.url.username.c_str(),size);
	strncat(dst, "123", size);
	return dst;
}

CExosipStack::CExosipStack(INT psaid) : m_psaid(psaid)
{

}

void * CExosipStack::thread_fun(void *data)
{
    timers_poll *my_timers = (timers_poll *)data;
    my_timers->run();

    return NULL;
}

string CExosipStack::generateRand(){
	srand((unsigned int) time(NULL));
	unsigned long int ra =  rand();
	stringstream ss;
	ss<<ra;
	string ran = ss.str();

	MD5 md5;
	md5.init();
	md5.UpdateMd5(ran.c_str(),ran.length());
	md5.Finalize();
	return  md5.GetMd5().substr(0,16);
}

int CExosipStack::sendInitRegister(timer * ptimer)
{
	//ptimer->timer_modify_internal(10.0);
	ptimer->timer_modify_internal(0);

	UserData * ud = (UserData *)ptimer->timer_get_userdata();


	string name  = ud->username;
	name.insert(0, "sip:");

	int reg_id = ud->reg_id;
	osip_message_t *reg = NULL;
	osip_message_init(&reg);

	eXosip_lock ();
	if(-1 == reg_id){


		reg_id = eXosip_register_build_initial_register(name.c_str(), realmAddr.c_str(), NULL, 3600, &reg);

		if(reg_id < 0)
		{
			eXosip_unlock ();
			//printf("reg_id<0\n");
			return -1;
		}

		ud->reg_id = reg_id;

		osip_route_t *rt;
		osip_route_init(&rt);
		char * response = new char[128];


		if (osip_route_parse(rt,proxy.c_str()) != 0)
		{
			//printf("proxy :%s\n", proxy.c_str());
			printf("Route does not parse!\n");
			return NULL;
		}
		else
		{
			osip_uri_uparam_add(rt->url,osip_strdup("lr"),NULL);
			osip_route_to_str(rt,&response);
		}

		osip_route_free(rt);

		osip_message_set_route(reg, response);
		delete []response;
		response = NULL;

		osip_message_set_supported(reg, "100rel");
		osip_contact_t *contact_header;
		osip_message_get_contact(reg, 0, &contact_header);
		osip_contact_param_add(contact_header, strdup("expires"), strdup("3600"));
		osip_contact_param_add(contact_header, strdup("+g.oma.sip-im"), NULL);
		osip_contact_param_add(contact_header, strdup("+g.oma.sip-im.large-message"), NULL);
	}
	else{
		eXosip_register_build_register(reg_id, 3600, &reg);
	}

	eXosip_unlock();

	eXosip_lock();

	char * buf = NULL;
		size_t len;
		osip_message_to_str(reg, &buf, &len);
		printf("register request:\n%s\n", buf);

	if(eXosip_register_send_register(reg_id, reg) != 0){
		eXosip_unlock();
		printf("send fail\n");
		return -1;
	}
	else{
		printf("send success!!\n");
	}
	eXosip_unlock();

	return 1;
}

int CExosipStack::getSipUserFromDB(timer *ptimer){

	set<string> name_pool;
	CSipUserManager::getSipUser(name_pool);
	//printf("username unregistered: %d\n", name_pool.size());
	double interval = 1;
	double starttime = 0;

	for(set<string>::iterator iter = m_name_pool.begin(); iter != m_name_pool.end(); ++iter){
		if(name_pool.find(*iter) == name_pool.end()){
			string uri = (*iter);
			uri.insert(0, "sip:");
			m_name_pool.erase(iter);
			timer * ptimer = m_map_timers[uri];
			ptimer_poll->timers_poll_del_timer(ptimer);
			//ptimer->timer_stop();
		}
	}

	for(set<string>::iterator iter = name_pool.begin(); iter != name_pool.end(); ++iter)
	{
		if(m_name_pool.find(*iter) == m_name_pool.end()){
			m_name_pool.insert(*iter);
			starttime += interval;
			UserData * ud = new UserData;
			ud->username = (*iter);
			ud->reg_id = -1;
			ud->noncecount = 1;
			ud->cnonce = generateRand();
			string uri = (*iter);
			uri.insert(0, "sip:");
			m_map_userdata.insert(make_pair<string, UserData *> (uri,ud));
			timer * ptimer = new timer(starttime, sendInitRegister, ud, 1);
			m_map_timers.insert(make_pair<string, timer *>(uri, ptimer));
			ptimer_poll->timers_poll_add_timer(ptimer);
		}
	}
	ptimer->timer_modify_internal(10);

	return 0;
}


void CExosipStack::register_process_401(eXosip_event_t * je)
{
	string name;


	name.append(osip_from_get_url(je->response->from)->scheme);
	name.append(":");
	name.append(osip_from_get_url(je->response->from)->username);
	name.append("@");
	name.append(osip_from_get_url(je->response->from)->host);
	UserData * ud = m_map_userdata[name];

	string cnonce = ud->cnonce;
	char * nc = new char [10];
	snprintf(nc, 9, "%.8x", ud->noncecount);
	string noncecount(nc);

	osip_www_authenticate_t * www_header;
	osip_message_get_www_authenticate(je->response, 0, &www_header);

	char * nonce64 = osip_www_authenticate_get_nonce(www_header);
	char * nonce64_no_quotes = remove_quotes(nonce64);

	string nonce = nonce64_no_quotes;


	string username;
	username.append(osip_from_get_url(je->response->from)->username);
	username.append("@");
	username.append(osip_from_get_url(je->response->from)->host);

	string password = CSipUserManager::getSipPassword(username);

	string realm = osip_from_get_url(je->response->from)->host;

	//aka_version = 1;
	char * alg;
	alg = osip_www_authenticate_get_algorithm(www_header);

	if(strcmp(alg, "MD5") != 0 /* && strcmp(alg, "AKAv1-MD5") != 0 && strcmp(alg, "AKAv2-MD5") != 0*/)
	{
		fprintf(stderr, "Authentication scheme %s not supported\n", alg);
		return;
	}
	string algorithm = alg;

	MD5Digest md5Digest(password,username,realm,nonce,cnonce, noncecount, algorithm);
	string response = md5Digest.calcResponse();
	//printf("response %s\n", response.c_str());

	osip_message_t * reg2 = NULL;
	int expires = 3600;

	map<string, UserData *>::iterator iter = m_map_userdata.find(name);
	if(iter == m_map_userdata.end()){
		return;
	}

	int reg_id = iter->second->reg_id;

	eXosip_lock();
	int r = eXosip_register_build_register(reg_id, expires, &reg2);
	eXosip_unlock();

	if(r < 0){
		fprintf(stderr, "error build register!!\n");
		return;
	}

	osip_header_t *expires_header;
	osip_message_get_expires(reg2, 0, &expires_header);
	char reg_expires_str[10];
	sprintf(reg_expires_str, "%d", expires);

	if(!strcmp(expires_header->hvalue, "3600")){
		osip_header_set_value(expires_header, osip_strdup(reg_expires_str));
	}

	osip_authorization_t *auth_header;
	osip_authorization_init(&auth_header);

	osip_authorization_set_auth_type(auth_header, "Digest");
	osip_authorization_set_realm(auth_header, add_quotes(realm));

	osip_authorization_set_algorithm(auth_header, alg);

	osip_authorization_set_message_qop(auth_header, "auth");

	osip_authorization_set_nonce(auth_header, add_quotes(nonce));

	osip_authorization_set_username(auth_header, add_quotes(username));

	osip_authorization_set_uri(auth_header, add_quotes(string("sip:")+realm));
	osip_authorization_set_response(auth_header, add_quotes(response));
	osip_authorization_set_cnonce(auth_header, add_quotes(cnonce));
	osip_authorization_set_nonce_count(auth_header, nc);

	//printf("before send\n");

	char * h_value;
	osip_authorization_to_str(auth_header, &h_value);
	//printf("h_value %s\n", h_value);

	if(osip_message_set_authorization(reg2, h_value) != 0)
		fprintf(stderr, "cannot set authorization\n");

	//printf("hello\n");
	eXosip_lock();
	int i = eXosip_register_send_register(reg_id, reg2);
	eXosip_unlock();

	if(i != 0){
		fprintf(stderr, "Error sending REGISTER\n");
		return;
	}

	//printf("send auth header successfully!\n");
	return;
}


void CExosipStack::register_process_200(eXosip_event_t * je)
{
	//printf("receive 200 OK\n");
	string username;
	username.append(osip_from_get_url(je->response->from)->username);
	username.append("@");
	username.append(osip_from_get_url(je->response->from)->host);

	CSipUserManager::setRegistered(username, true);

	// get list of service routes from 200 OK response
	osip_header_t *service_route;
	int num_routes = 0;
	int num_service_routes = 0;
	vector<char *> ims_service_route;
	while(osip_message_header_get_byname(je->response, "Service-Route", num_routes, &service_route) >= 0)
	{
		if((num_service_routes == 0) || (strcmp(osip_header_get_value(service_route), ims_service_route[num_service_routes-1]) != 0))
		{
			//printf("****service route: %s\n", osip_header_get_value(service_route));

			ims_service_route.push_back(osip_header_get_value(service_route));
			++ num_service_routes;
		}
		++ num_routes;
	}

	int expires = 1800;
	osip_contact_t * contact;

	if(osip_message_get_contact(je->response, 0, &contact) >= 0)
	{
		osip_generic_param_t * params;
		if(osip_contact_param_get_byname(contact, "Expires", &params) >= 0){
			expires = atoi(params->gvalue);
			expires = expires >> 1;
		//	printf("sip-psa: get expires from contact param:%d\n", expires);
		}
	}

	osip_header_t * exp;
	if(osip_message_get_expires(je->response, 0, &exp) >= 0){
		expires = atoi(exp->hvalue);
		expires = expires >> 1;
		printf("sip-psa: get expires from header Expires:%d\n", expires);
	}


	string uri = username;
	uri.insert(0, "sip:");

	if(!ims_service_route.empty())
	{
		m_service_route.insert(make_pair<string, vector<char *> >(uri, ims_service_route));
	}

	timer * ptimer = m_map_timers[uri];
	ptimer->timer_modify_internal(expires);
	//ptimer->timer_start();


	return;
}

char * CExosipStack::remove_quotes(char * text)
{
	char * rep = strtok(text, "\"");
	return osip_strdup(rep);
}

char * CExosipStack::add_quotes(string text)
{
	text.insert(0, "\"", 1);
	text.append("\"");

	char * res = new char[text.length()+1];
	strcpy(res, text.c_str());
	return res;
}




BOOL CExosipStack::init(USHORT port)
{

	if (eXosip_init() != 0)
	{
		// 初始化失败
		psaErrorLog(this->m_psaid, "eXosip Init Failed\n");
		return FALSE;
	}

	// 打开监听端口
	if (eXosip_listen_addr(IPPROTO_UDP, NULL, port, AF_INET, FALSE) != 0)
	{
		psaErrorLog(this->m_psaid, "eXosip listen on port %d failed\n", port);
		eXosip_quit();
		return FALSE;
	}
	psaPrint(this->m_psaid, "eXosip listening on port %d\n", port);

	CProperties* properties = CPropertiesManager::getInstance()->getProperties("gateway.env");
	int accessMode = properties->getIntProperty("accessMode");

	if(accessMode == -1){
		printf("AccessMode not set in mcf.env, Use DEFAULT");
		accessMode = 0;
	}
	else{
		printf("Read env get accessMode %d\n", accessMode);
		this->accessMode = accessMode;
	}

	confType = properties->getProperty("confType");
	if(confType != ""){
		confServer = "sip:" + properties->getProperty("confServer");
		if(confServer == ""){
			confServer = "sip:10.109.247.115:5060";
		}
		confRealm = properties->getIntProperty("confRealm");
		if(confRealm == ""){
			confRealm = "conf.com";
		}
	}

	if(accessMode == 2){
		ptimer_poll = new timers_poll(128);
		thread_id = 0;

		if(pthread_create(&thread_id, NULL, thread_fun, (void *)ptimer_poll) != 0){
			printf("create failed\n");
			return FALSE;
		}
	}

	if(1 == accessMode){
		proxy = properties->getProperty("proxy");
		proxy = "sip:" + proxy;
		CSipUserManager::setAllRegistered(true);
	}
	else if(2 == accessMode){
		proxy = properties->getProperty("proxy");
		proxy = "sip:" + proxy;

		_realmAddr = properties->getProperty("realmAddr");
		realmAddr = "sip:" + _realmAddr;

		CSipUserManager::init();
		timer * ptimer = new timer(1, getSipUserFromDB, NULL, 1);
		ptimer_poll->timers_poll_add_timer(ptimer);


	}
	else{
		icscf = properties->getProperty("icscf");
		icscf = "sip:" + icscf;
	}


	return TRUE;
}

void CExosipStack::doActive(void)
{
	BOOL parsed = FALSE; // 标记消息是否被处理


	eXosip_event_t* event = eXosip_event_wait(0, 0);
	if (NULL == event) return;


	DEBUGV(m_psaid, "eXosip receive message: type: %d\n", event->type);
	DEBUGV(m_psaid, "eXosip textinfo: %s\n", event->textinfo);
	DEBUGV(m_psaid, "eXosip tid: %d\n", event->tid);
	DEBUGV(m_psaid, "eXosip cid: %d\n", event->cid);
	DEBUGV(m_psaid, "eXosip ACK: %d\n", (int) event->ack);

	if(event->request == NULL && event->response == NULL)
	{
		return;
	}

	char * buf = NULL;
	size_t len;
	osip_message_to_str(event->request, &buf, &len);
	printf("eXosip message request:\n%s\n", buf);

	osip_message_to_str(event->response, &buf, &len);
	printf("eXosip message response:\n%s\n", buf);
	printf("eXosip receive message: type: %d\n", event->type);


	// Set Ctrl Msg

	PTSipCtrlMsg pCtrlMsg = new TSipCtrlMsg();
	PTUniNetMsg pMsg = new TUniNetMsg();

	pMsg->msgType = SIP_TYPE;

	pMsg->oAddr.logAddr = m_psaid;
	pMsg->tAddr.logAddr = CSipEnv::instance()->DIS_LOG_ADDR;

	pMsg->dialogType = DIALOG_BEGIN;

	// Build header
	pMsg->ctrlMsgHdr = pCtrlMsg;
	pMsg->setCtrlMsgHdr();

	if (event->request && MSG_IS_REGISTER(event->request))
	{
		if (event->response == NULL) {
			// a request message

			parsed = TRUE;

			osip_message_t* ans = NULL;
			int ret;

			eXosip_lock();
			ret = eXosip_message_build_answer(event->tid, 501, &ans);
			if (OSIP_SUCCESS != ret)
			{
				psaPrint(m_psaid,
						"eXosip_message_build_answer error for register!!!\n");
			}
			else
			{

				ans->reason_phrase = osip_strdup("Not Implemented");
				ret = eXosip_message_send_answer(event->tid, 501, ans);
				if (OSIP_SUCCESS != ret)
				{
					psaPrint(m_psaid,"error send answer for register!!!\n"
							);
				}
			}
			eXosip_unlock();
			delete pMsg;

			DEBUG0(m_psaid, "eXosip event free!");
			eXosip_event_free(event);

			return;

		}
	}
	else if(event->request && MSG_IS_OPTIONS(event->request)){
		//OPTIONS message
		if(event->response == NULL){
			parsed = TRUE;
		//	osip_message_t * opt = event->request;

			osip_message_t * ans;
			eXosip_options_build_answer(event->tid, 200, &ans);

			osip_message_set_allow(ans, "ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, OPTIONS, PRACK, REGISTER, UPDATE");
			osip_message_set_accept(ans, "application/sdp");
			osip_message_set_accept_language(ans, "da, en-gb; q= 0.8, en;q=0.7");
			eXosip_options_send_answer(event->tid, 200, ans);
		}

	}
	else
	{
		switch (event->type)
		{
		case EXOSIP_REGISTRATION_FAILURE:
		{
			printf("REGISTER FAILURE!!!!\n");
			break;
		}
		case EXOSIP_REGISTRATION_SUCCESS:
		{
			printf("REGISTER SUCCESS!!!!\n");
			break;
		}

		case EXOSIP_CALL_INVITE:
		{
			parsed = TRUE;

			osip_message_t *invite = event->request;
			PTSipInvite mcfInvite = new TSipInvite();

			ExosipTranslator::convertOsipInvite2MCF(invite, *mcfInvite);

			pMsg->msgName = SIP_INVITE;
			pMsg->msgBody = mcfInvite;
			pMsg->setMsgBody();

			ExosipTranslator::convertCtrlMsg2MCF(event->request, pCtrlMsg);

			// add to tag to invite since upper app can't control eXosip of outgoing msg
			// retrive it from 101 response generated by eXosip
			ExosipTranslator::convertOsipTo2MCF(event->response->to, pCtrlMsg->to);

			this->m_map_branch_tid.put(pCtrlMsg->via.branch.c_str(), event->tid);


			this->storeCid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId,
					event->cid);

			break;
		}
		case EXOSIP_CALL_REINVITE:
		{
			parsed = TRUE;

			osip_message_t *invite = event->request;
			PTSipInvite mcfInvite = new TSipInvite();
			ExosipTranslator::convertOsipInvite2MCF(invite, *mcfInvite);

			pMsg->msgName = SIP_INVITE;
			pMsg->msgBody = mcfInvite;
			pMsg->setMsgBody();

			ExosipTranslator::convertCtrlMsg2MCF(event->request, pCtrlMsg);
			// add to tag to invite since upper app can't control eXosip of outgoing msg
			// retrive it from 101 response generated by eXosip
			// re-invite msg have to-tag, no need to attach
//			ExosipTranslator::convertOsipTo2MCF(event->response->to, pCtrlMsg->to);

			// needed, branch changed
			this->m_map_branch_tid.put(pCtrlMsg->via.branch.c_str(), event->tid);

//			this->storeCid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId,
//					event->cid);
			break;
		}
		case EXOSIP_CALL_PROCEEDING:
		{
//			if (100 == event->response->status_code)
//			{
//				// store call id for outgoing invite
//				this->storeCid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId,
//						event->cid);
//			}
//			else if (101 == event->response->status_code)
//			{
//				// Dialog established
//				this->storeDid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId,
//									event->did);
//			}
			break;
		}
		case EXOSIP_CALL_ANSWERED:
		{
			parsed = TRUE;

			osip_message_t *resp = event->response;

			PTSipResp mcfResp = new TSipResp();

			ExosipTranslator::convertOsipResp2MCF(resp, *mcfResp);

			pMsg->msgName = SIP_RESPONSE;
			pMsg->msgBody = mcfResp;
			pMsg->setMsgBody();

			ExosipTranslator::convertCtrlMsg2MCF(event->response, pCtrlMsg);

			this->storeCid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId,
								event->cid);
			this->storeDid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId,
								event->did);

			break;
		}
		case EXOSIP_CALL_ACK:
		{
			parsed = TRUE;

			osip_message_t *ack = event->ack;

			PTSipReq mcfAck = new TSipReq();

			ExosipTranslator::convertOsipReq2MCF(ack, *mcfAck);

			pMsg->msgName = SIP_ACK;
			pMsg->msgBody = mcfAck;
			pMsg->setMsgBody();

			ExosipTranslator::convertCtrlMsg2MCF(event->ack, pCtrlMsg);

			this->storeDid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId,
					event->did);

			break;
		}
		case EXOSIP_CALL_MESSAGE_NEW:
		{
			if (!strcmp(event->request->sip_method, "BYE"))
			{
				// It will be handled in EXOSIP_CALL_CLOSED
				parsed = TRUE;

				delete pMsg;

				DEBUG0(m_psaid, "eXosip event free!");
				eXosip_event_free(event);

				return;
			}
			else if (!strcmp(event->request->sip_method, "INFO")){
				parsed = TRUE;

				osip_message_t *info = event->request;

				PTSipInfo mcfInfo = new TSipInfo();

				ExosipTranslator::convertOsipInfo2MCF(info, *mcfInfo);

				pMsg->msgName = SIP_INFO;
				pMsg->msgBody = mcfInfo;
				pMsg->setMsgBody();
				ExosipTranslator::convertCtrlMsg2MCF(info, pCtrlMsg);
				this->m_map_branch_tid.put(pCtrlMsg->via.branch.c_str(), event->tid);
				this->storeDid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId,
						event->did);

				break;
			}

		}
		case EXOSIP_CALL_RELEASED:
		{
			parsed = TRUE;

			delete pMsg;

			DEBUG0(m_psaid, "eXosip event free!");
			eXosip_event_free(event);

			return;
		}
		case EXOSIP_CALL_CLOSED:
		{
			// Receive BYE or CANCEL
			parsed = TRUE;

			ExosipTranslator::convertCtrlMsg2MCF(event->request, pCtrlMsg);

			osip_cseq_t* cseq = osip_message_get_cseq(event->request);
			if (NULL != event->response && 487 != event->response->status_code
					&& strcmp("BYE", cseq->method))
			{
				DEBUGV(m_psaid, "status_code: %d\n", event->response->status_code);
				// A non-487 is sent out! by psa, ACK is received
				PTSipReq declineAck = new TSipReq();
				declineAck->req_uri = pCtrlMsg->to.url;
				pMsg->msgName = SIP_ACK;
				pMsg->msgBody = declineAck;
				pMsg->setMsgBody();

				ExosipTranslator::convertCtrlMsg2MCF(event->response, pCtrlMsg);
				// Change Cseq Method to ACK
				pCtrlMsg->cseq_method = "ACK";
				// TODO: uncorect Cseq number
			}
			else if (!strcmp(event->request->sip_method, "CANCEL"))
			{
				// CANCEL is received
				PTSipCancel mcfCancel = new TSipCancel();

				ExosipTranslator::convertOsipCancel2MCF(event->request, *mcfCancel);
				ExosipTranslator::convertCtrlMsg2MCF(event->response, pCtrlMsg);
				pCtrlMsg->cseq_method = "CANCEL";
				pMsg->msgName = SIP_CANCEL;
				pMsg->msgBody = mcfCancel;
				pMsg->setMsgBody();
			}
			else
			{
				// BYE received
				PTSipBye mcfBye = new TSipBye();

				ExosipTranslator::convertOsipBye2MCF(event->request, *mcfBye);
				pMsg->msgName = SIP_BYE;
				pMsg->msgBody = mcfBye;
				pMsg->setMsgBody();
			}

			this->removeCid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId);
			this->removeDid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId);

			// in case the callee send bye
			this->removeCid(pCtrlMsg->to, pCtrlMsg->from, pCtrlMsg->sip_callId);
			this->removeDid(pCtrlMsg->to, pCtrlMsg->from, pCtrlMsg->sip_callId);
			break;
		}
		case EXOSIP_MESSAGE_NEW:
		{
			parsed = TRUE;

			osip_message_t *msg = event->request;

			PTSipMessage mcfMsg = new TSipMessage();

			ExosipTranslator::convertOsipMessage2MCF(msg, *mcfMsg);
			ExosipTranslator::convertOsipContentType2MCF(msg->content_type,
					mcfMsg->content_type);

			pMsg->msgName = SIP_MESSAGE;
			pMsg->msgBody = mcfMsg;
			pMsg->setMsgBody();

			ExosipTranslator::convertCtrlMsg2MCF(event->request, pCtrlMsg);

			this->m_map_branch_tid.put(pCtrlMsg->via.branch.c_str(), event->tid);

			break;
		}

		case EXOSIP_IN_SUBSCRIPTION_NEW:
		{
			// TODO: WARNING end subscription message here. ERRRRRRRRRRRRRR
			parsed = TRUE;
			eXosip_lock();
			osip_message_t* ans = NULL;
			eXosip_insubscription_build_answer(event->tid, 200, &ans);
			eXosip_insubscription_send_answer(event->tid, 200, ans);
			eXosip_unlock();
			break;
		}
		default:
			psaPrint(m_psaid, "UNHANDLED exosip event: %d\n", event->type);
			break;
		} // switch event->type
	} // is REGISTER or not

	if (!parsed)
	{
		if (event->response && MSG_IS_RESPONSE(event->response))
		{
			parsed = TRUE;

			if (0 == strcmp(event->response->cseq->method, "REGISTER"))
			{
				if(2 == accessMode)
				{
					if (200 == event->response->status_code)
					{
						// REGISTER response 200OK, clear rid map
						register_process_200(event);
						return;
					}
					else if(401 == event->response->status_code)
					{
						register_process_401(event);
						return;
					}
					else{
						return;
					}
				}
				else{
					//不处理注册消息
					return;
				}
			}
			if (0 == strcmp(event->response->cseq->method, "PRACK"))
			{
				return;
			}

			osip_message_t *resp = event->response;

			PTSipResp mcfResp = new TSipResp();

			ExosipTranslator::convertOsipResp2MCF(resp, *mcfResp);

			pMsg->msgName = SIP_RESPONSE;
			pMsg->msgBody = mcfResp;
			pMsg->setMsgBody();

			ExosipTranslator::convertCtrlMsg2MCF(event->response, pCtrlMsg);

			if (MSG_IS_STATUS_1XX(event->response))
			{
				// keep cid here
				this->storeCid(pCtrlMsg->from, pCtrlMsg->to,
						pCtrlMsg->sip_callId, event->cid);
			}
			if (101 <= event->response->status_code && 180
					>= event->response->status_code)
			{
				// keep did
				this->storeDid(pCtrlMsg->from, pCtrlMsg->to,
						pCtrlMsg->sip_callId, event->did);

				osip_header_t * requireHd;
				if(osip_message_get_require(event->request, 0, &requireHd) >= 0){
					string requireStr = requireHd->hvalue;
					if(requireStr.find("100rel") != string::npos){
						osip_message_t *prack;
						eXosip_call_build_prack(event->tid, &prack);
						eXosip_call_send_prack(event->tid, prack);

					}
				}

			}
		}
	} // if not parsed

	if (!parsed)
	{
		delete pMsg;
		psaPrint(m_psaid, "ERROR: UNKNOWN Sip Message Type!\n");

		DEBUG0(m_psaid, "eXosip event free!");
		eXosip_event_free(event);

		return;
	}

	PTMsg mcfMsg = new TMsg();
	// Send out message
	CMsgConvertor::convertMsg(pMsg, mcfMsg);
	sendMsgToPACM(mcfMsg);

	DEBUG0(m_psaid, "eXosip event free!");
	eXosip_event_free(event);
}

BOOL CExosipStack::doSendMsg(PTMsg msg)
{
	PTUniNetMsg uniMsg = (PTUniNetMsg) msg->pMsgPara;
	BOOL flag = FALSE;

	if (NULL == uniMsg)
	{
		return flag;
	}

	switch (uniMsg->msgName)
	{
	case SIP_RESPONSE:
	{
		flag = this->onSend_SIP_RESPONSE(uniMsg);
		break;
	} // case SIP_RESPONSE
	case SIP_ACK:
	{
		flag = this->onSend_SIP_ACK(uniMsg);
		break;
	} // case SIP_ACK
	case SIP_BYE:
	{
		flag = this->onSend_SIP_BYE(uniMsg);
		break;
	} // SIP_BYE
	case SIP_INVITE:
	{
		//CTUniNetMsgHelper::print(uniMsg);
		flag = this->onSend_SIP_INVITE(uniMsg);
		break;
	} // SIP_INVITE
	case SIP_MESSAGE:
	{
		flag = this->onSend_SIP_MESSAGE(uniMsg);
		break;
	}
	case SIP_CANCEL:
	{
		flag = this->onSend_SIP_CANCEL(uniMsg);
		break;
	}
	case SIP_REGISTER:
	{
		flag = this->onSend_SIP_REGISTER(uniMsg);
		break;
	}
	default:
		break;
	}

	return flag;
}

BOOL CExosipStack::onSend_SIP_RESPONSE(PCTUniNetMsg uniMsg)
{
	PTSipResp mcfRes = (PTSipResp) uniMsg->msgBody;
	PTSipCtrlMsg pCtrlMsg = (PTSipCtrlMsg) uniMsg->ctrlMsgHdr;

	printf("Send out SIP RESPONSE: status = %d!!!!!!!!\n",
			mcfRes->statusCode);


	if (!strcmp(pCtrlMsg->cseq_method.c_str(), "INVITE"))
	{
		if (100 == mcfRes->statusCode)
		{
			// 100 trying is sent by eXosip automatically
			return TRUE;
		}
		else if (603 == mcfRes->statusCode)
		{
			// Decline
			//return onSend_SIP_BYE(uniMsg);
		}

		INT tid = -1;
		if (this->m_map_branch_tid.get(pCtrlMsg->via.branch.c_str(), tid))
		{
			osip_message_t *ans = NULL;

			int ret;

			eXosip_lock();
			ret = eXosip_call_build_answer(tid, mcfRes->statusCode, &ans);
			if (OSIP_SUCCESS != ret)
			{
				printf("eXosip can't build answer: %d!\n", ret);
			}
			else
			{
				// HHP: modified by Huang Haiping 2010-09-09 fix crash when build failed
				ExosipTranslator::convertMCF2OsipResp(*mcfRes, ans);


				if(isConfCall(pCtrlMsg->from.url.username.c_str()) == true){
					osip_route_t *rt;
					osip_route_init(&rt);
					string confServerAddr = (string)"<" + confServer + ";lr>";
					osip_message_set_route(ans, confServerAddr.c_str());
				}
				else{
					if(accessMode == 0)
					{
						osip_route_t *rt;
						osip_route_init(&rt);
						string icscfAddr = (string)"<" + icscf + ";lr>";
						osip_message_set_route(ans, icscfAddr.c_str());
					}
					else{
						osip_route_t *rt;
						osip_route_init(&rt);
						string proxyAddr = (string)"<" + proxy + ";lr>";
						osip_message_set_route(ans, proxyAddr.c_str());
					}
				}

				ExosipTranslator::convertMCF2CtrlMsg(pCtrlMsg, ans);

				char * buf = NULL;
				size_t len;
				osip_message_to_str(ans, &buf, &len);

				printf("****answer:\n%s\n", buf);



				ret = eXosip_call_send_answer(tid, mcfRes->statusCode, ans);
				if (OSIP_SUCCESS != ret)
				{
					psaPrint(m_psaid, "eXosip_call_send_answer %d failed: %d!!!\n",
							mcfRes->statusCode, ret);
				}
				else
				{
					DEBUG0(m_psaid, "eXosip_call_send_answer success!!!\n");
				}
			}

			eXosip_unlock();
			if (200 == mcfRes->statusCode)
			{
				// Final response terminates the transaction
				this->m_map_branch_tid.remove(pCtrlMsg->via.branch.c_str());
			}
		}
		else
		{
			psaPrint(m_psaid, "UNKNOW Transaction: %s\n",
					pCtrlMsg->via.branch.c_str());
		}
	} // RESPONSE for INVITE
	else if (!strcmp(pCtrlMsg->cseq_method.c_str(), "REGISTER") || !strcmp(
			pCtrlMsg->cseq_method.c_str(), "MESSAGE"))
	{
		INT tid = -1;
		if (this->m_map_branch_tid.get(pCtrlMsg->via.branch.c_str(), tid))
		{
			osip_message_t* ans = NULL;
			int ret;

			eXosip_lock();
			ret = eXosip_message_build_answer(tid, mcfRes->statusCode, &ans);
			if (OSIP_SUCCESS != ret)
			{
				psaPrint(m_psaid, "eXosip_message_build_answer %d failed: %d!!!\n",
										mcfRes->statusCode, ret);
			}
			else
			{
				ExosipTranslator::convertMCF2OsipResp(*mcfRes, ans);

				ret = eXosip_message_send_answer(tid, mcfRes->statusCode, ans);
				if (OSIP_SUCCESS != ret) {
					psaPrint(m_psaid,
							"eXosip_message_send_answer %d failed: %d!!!\n",
							mcfRes->statusCode, ret);
				}
			}
			eXosip_unlock();

			this->m_map_branch_tid.remove(pCtrlMsg->via.branch.c_str());
		}
		else
		{
			psaPrint(m_psaid, "UNKNOW Transaction: %s\n",
					pCtrlMsg->via.branch.c_str());
		}
	} // RESPONSE for REGISTER/MESSAGE
	else if (!strcmp(pCtrlMsg->cseq_method.c_str(), "BYE"))
	{
		// 200 ok is required to be sent and have been sent automatically by eXosip
	} // RESPONSE for BYE
	else if(!strcmp(pCtrlMsg->cseq_method.c_str(), "INFO"))
	{
		INT tid = -1;
		if (this->m_map_branch_tid.get(pCtrlMsg->via.branch.c_str(), tid))
		{
			printf("build response\n");
			osip_message_t* ans = NULL;
			int ret;

			eXosip_lock();
			ret = eXosip_call_build_answer(tid, mcfRes->statusCode, &ans);
			//ret = eXosip_message_build_answer();
			if (OSIP_SUCCESS != ret)
			{
				printf("eXosip_message_build_answer %d failed: %d!!!\n",
						mcfRes->statusCode, ret);
			}
			else
			{
				ExosipTranslator::convertMCF2OsipResp(*mcfRes, ans);
				char * buf = NULL;
				size_t len;
				osip_message_to_str(ans, &buf, &len);
				//ret = eXosip_message_send_answer(tid, mcfRes->statusCode, ans);
				ret = eXosip_call_send_answer(tid, mcfRes->statusCode, ans);
				if (OSIP_SUCCESS != ret) {
					psaPrint(m_psaid,
							"eXosip_message_send_answer %d failed: %d!!!\n",
							mcfRes->statusCode, ret);
				}
			}
			eXosip_unlock();
			this->m_map_branch_tid.remove(pCtrlMsg->via.branch.c_str());
		}
	}
	else
	{
		psaPrint(m_psaid, "UNHANDLED sip method: %s\n", pCtrlMsg->cseq_method.c_str());
	}

	return TRUE;
}

BOOL CExosipStack::onSend_SIP_ACK(PCTUniNetMsg uniMsg)
{
	PTSipCtrlMsg pCtrlMsg = (PTSipCtrlMsg) uniMsg->ctrlMsgHdr;

	DEBUG0(m_psaid, "Send out SIP ACK!!!!!!!!\n");
	INT did = -1;
	//this->m_map_dialogid.getNext(did);

	did = this->getDid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId);
	//printf("&&&&&callId == %s", pCtrlMsg->sip_callId.number.c_str());
	//printf("&&&&&did = %d, len= %d\n", did, m_map_dialogid.size());

	if (did != -1)
	{
		osip_message_t* ack = NULL;
		int ret;

		eXosip_lock();
		ret = eXosip_call_build_ack(did, &ack);
		if (ret != OSIP_SUCCESS) {
			psaPrint(m_psaid, "eXosip_call_build_ack failed: %d"
				"\t(-6:OSIP_NOTFOUND -2:OSIP_BADPARAMETER\n", ret);
		}
		else
		{
			// try to fix ack send failed
			osip_via_t * via = (osip_via_t *) osip_list_get (&ack->vias, 0);
			if (via == NULL || via->protocol == NULL)
			{
				DEBUG0(m_psaid, "via == NULL || via->protocol == NULL\n");
			}
			else
			{
				DEBUG0(m_psaid, "via OK\n");
				char* buf = NULL;
				size_t len;
				osip_message_to_str(ack, &buf, &len);
				DEBUGV(m_psaid, "%s\n", buf);
				osip_free(buf);
			}
			// try to fix ack send failed END
			//ExosipTranslator::convertMCF2CtrlMsg(pCtrlMsg, ack);

//			if(isConfCall(pCtrlMsg->to.url.username.c_str()) == true){
//				osip_route_t *rt;
//				osip_route_init(&rt);
//				string confServerAddr = (string)"<" + confServer + ";lr>";
//				osip_message_set_route(ack, confServerAddr.c_str());
//			}


//			if(accessMode == 0)
//			{
//				osip_route_t *rt;
//				osip_route_init(&rt);
//				string icscfAddr = (string)"<" + icscf + ";lr>";
//				osip_message_set_route(ack, icscfAddr.c_str());
//			}
//			else{
//				osip_route_t *rt;
//				osip_route_init(&rt);
//				string proxyAddr = (string)"<" + proxy + ";lr>";
//				osip_message_set_route(ack, proxyAddr.c_str());
//
//			}

			char * buf = NULL;
			size_t len;
			osip_message_to_str(ack, &buf, &len);
			printf("****ACK:\n%s\n", buf);
			ret = eXosip_call_send_ack(did, ack);

			if (ret != OSIP_SUCCESS)
			{
				psaPrint(m_psaid, "eXosip_call_send_ack failed: %d"
						"\t(-6:OSIP_NOTFOUND -2:OSIP_BADPARAMETER\n", ret);
			}
		}
		eXosip_unlock();
		return TRUE;
	}
	else
	{
		psaPrint(m_psaid, "UNKNOW Dialog for sending ACK\n");
		return FALSE;
	}
}

BOOL CExosipStack::onSend_SIP_BYE(PCTUniNetMsg uniMsg)
{
	DEBUG0(m_psaid, "Terminating Call\n");
	//printf("**** psa received bye\n");
	INT did = -1;
	INT cid = -1;
	BOOL revert = false; // revert from,to?

	PTSipCtrlMsg pCtrlMsg = (PTSipCtrlMsg) uniMsg->ctrlMsgHdr;

	did = this->getDid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId);
	cid = this->getCid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId);

	if (-1 == cid)
	{
		// revert from to
		did = this->getDid(pCtrlMsg->to, pCtrlMsg->from, pCtrlMsg->sip_callId);
		cid = this->getCid(pCtrlMsg->to, pCtrlMsg->from, pCtrlMsg->sip_callId);
		revert = TRUE;
	}

	if (cid != -1)
	{
		DEBUGV(m_psaid, "eXosip_call_terminate: cid[%d] did[%d]\n", cid, did);
		eXosip_lock();

//		if(isConfCall(pCtrlMsg->from.url.username.c_str()) == true){
//			osip_route_t *rt;
//			osip_route_init(&rt);
//			string confServerAddr = (string)"<" + confServer + ";lr>";
//			osip_message_set_route(ans, confServerAddr.c_str());
//		}

//		if(accessMode == 0){
//			string icscfAddr = (string)"<" + icscf +";lr>";
//			const char * nexthop = icscfAddr.c_str();
//			status = eXosip_call_terminate(cid, did, nexthop);
//		}
//		else{
//			string proxyAddr = (string)"<" + icscf +";lr>";
//			const char * nexthop = proxyAddr.c_str();
//			status = eXosip_call_terminate(cid, did, nexthop);
//		}

		int status = eXosip_call_terminate(cid, did);
		//printf("#####send bye status:%d\n", status);
		eXosip_unlock();
		if (OSIP_SUCCESS != status)
		{
			psaPrint(m_psaid, "eXosip_call_terminate failed: %d!\n", status);
		}
		if (!revert)
		{
			this->removeCid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId);
			this->removeDid(pCtrlMsg->from, pCtrlMsg->to, pCtrlMsg->sip_callId);
		}
		else
		{
			this->removeCid(pCtrlMsg->to, pCtrlMsg->from, pCtrlMsg->sip_callId);
			this->removeDid(pCtrlMsg->to, pCtrlMsg->from, pCtrlMsg->sip_callId);
		}
		if (pCtrlMsg->via.branch.length() > 0)
		{
			// remove transaction id map
			this->m_map_branch_tid.remove(pCtrlMsg->via.branch.c_str());
		}
		return TRUE;
	}
	else
	{
		psaPrint(m_psaid, "BYE to unknown dialog!!!!!\n");
		return FALSE;
	}
}

BOOL CExosipStack::onSend_SIP_CANCEL(PCTUniNetMsg uniMsg)
{
	DEBUG0(m_psaid, "Send out SIP CANCEL!!!!!!!!\n");
	return this->onSend_SIP_BYE(uniMsg);
}

BOOL CExosipStack::onSend_SIP_INVITE(PCTUniNetMsg uniMsg)
{
	DEBUG0(m_psaid, "###########onSend_SIP_INVITE\n");
	PTSipCtrlMsg pCtrlMsg = (PTSipCtrlMsg) uniMsg->ctrlMsgHdr;

	PTSipInvite mcfInvite = (PTSipInvite) uniMsg->msgBody;

	// TODO: 是否在新消息中增加via字段填充？

	//printf("sip-psa receive INVITE, \n");

	CVarChar routeStr;
	if (pCtrlMsg->route.url.host.length() > 0)
	{
		DEBUGV(m_psaid, "OUTGOING SIP INVITE route before convert: %s\n",
							pCtrlMsg->route.url.host.c_str());

		routeStr = CSipMsgHelper::toStringRoute(pCtrlMsg->route);

		DEBUGV(m_psaid, "OUTGOING SIP INVITE route after convert: %s\n",
							routeStr.c_str());
	}

	osip_message_t *invite = NULL;
	int ret = eXosip_call_build_initial_invite(&invite,
			CSipMsgHelper::toString(pCtrlMsg->to).c_str(),
			CSipMsgHelper::toString(pCtrlMsg->from).c_str(),
			(routeStr.length() > 0) ? routeStr.c_str(): NULL,
			NULL);
	if (OSIP_SUCCESS != ret)
	{
		psaPrint(m_psaid, "eXosip_call_build_initial_invite failed!\n");
		return FALSE;
	}

	if(isConfCall(pCtrlMsg->to.url.username.c_str()) == true){
		string confServerAddr = (string)"<" + confServer + ";lr>";
		osip_message_set_route(invite, confServerAddr.c_str());
	}
	else
	{
		if(1 == accessMode){
			osip_route_t *rt;
			osip_route_init(&rt);
			char * response = new char[128];

			if (osip_route_parse(rt,proxy.c_str()) != 0)
			{
				printf("Route does not parse!\n");
				return NULL;
			}
			else
			{
				osip_uri_uparam_add(rt->url,osip_strdup("lr"),NULL);
				osip_route_to_str(rt,&response);
			}

			osip_route_free(rt);
			osip_message_set_route(invite, response);

		}
		else if(2 == accessMode)
		{
			osip_route_t *rt;
			osip_route_init(&rt);
			char * response = new char[128];


			if (osip_route_parse(rt,proxy.c_str()) != 0)
			{
				printf("Route does not parse!\n");
				return NULL;
			}
			else
			{
				osip_uri_uparam_add(rt->url,osip_strdup("lr"),NULL);
				osip_route_to_str(rt,&response);
			}

			osip_route_free(rt);
			osip_message_set_route(invite, response);

			string url = "sip:";
			url.append(osip_from_get_url(invite->from)->username);
			url.append("@");
			url.append(osip_from_get_url(invite->from)->host);

			if(m_service_route.find(url) != m_service_route.end())
			{
				vector<char *> vec = m_service_route[url];
				vector<char*>::reverse_iterator it = vec.rbegin();
				//printf("sippsa::::accessMode = 1; from url: %s, service route:\n", url.c_str());
				while(it != vec.rend())
				{
					//printf("*****service route: %s\n", *it);
					osip_message_set_route(invite, (*it));
					it++;
				}
			}
		}
		else{
			osip_route_t *rt;
			osip_route_init(&rt);
			string icscfAddr = (string)"<" + icscf + ";lr>";
			osip_message_set_route(invite, icscfAddr.c_str());
		}
	}

	char * buf1 = NULL;
	size_t len1;
	osip_message_to_str(invite, &buf1, &len1);

	ExosipTranslator::convertMCF2CtrlMsg(pCtrlMsg, invite);
	ExosipTranslator::fillOsipBody(mcfInvite->body, mcfInvite->content_type, invite);
		//added by liling 2010-7 to add ROUTE to out-going SIP message
	char* buf = NULL;
	size_t len;
	osip_message_to_str(invite, &buf, &len);
	DEBUGV(m_psaid, "%s\n", buf);

	printf("******************send invite \n%s\n", buf);
	osip_free(buf);

	eXosip_lock();
	eXosip_call_send_initial_invite(invite);
	eXosip_unlock();

//	time_t timel;
//	time(&timel);
//	printf("\n %s ####sip-psa count= %d\n\n", ctime(&timel), ++count);

	return TRUE;
}

BOOL CExosipStack::onSend_SIP_REGISTER(PCTUniNetMsg uniMsg)
{
	PTSipCtrlMsg pCtrlMsg = (PTSipCtrlMsg) uniMsg->ctrlMsgHdr;

	PTSipRegister mcfRegister = (PTSipRegister) uniMsg->msgBody;

	osip_message_t *reg = NULL;
	INT rid = 0;
	rid = eXosip_register_build_initial_register(
			CSipMsgHelper::toString(pCtrlMsg->from).c_str(),
			CSipMsgHelper::toString(mcfRegister->req_uri).c_str(),
			CSipMsgHelper::toString(mcfRegister->contact).c_str(),
			mcfRegister->expires, &reg);

	ExosipTranslator::convertMCF2CtrlMsg(pCtrlMsg, reg);

	eXosip_lock();
	int ret = eXosip_register_send_register(rid, reg);
	eXosip_unlock();

	if (OSIP_SUCCESS != ret)
	{
		psaPrint(m_psaid, "Send REGISTER failed!!!\n");
		return FALSE;
	}
	else
	{
		DEBUGV(m_psaid, "keep exosip register rid: %d\n", rid);
		//m_map_registerid.put(CSipMsgHelper::toString(pCtrlMsg->from.url).c_str(), rid);
	}

	return TRUE;
}

BOOL CExosipStack::onSend_SIP_MESSAGE(PCTUniNetMsg uniMsg)
{
	PTSipCtrlMsg pCtrlMsg = (PTSipCtrlMsg) uniMsg->ctrlMsgHdr;

	PTSipMessage mcfMsg = (PTSipMessage) uniMsg->msgBody;
	osip_message_t *msg = NULL;

	CVarChar routeStr;

	DEBUGV(m_psaid, "###########onSend_SIP_MESSAGE to: %s\n",
			CSipMsgHelper::toString(pCtrlMsg->to).c_str());

	if (pCtrlMsg->route.url.host.length() > 0)
	{
		DEBUGV(m_psaid, "OUTGOING SIP MSG route before convert: %s\n",
						pCtrlMsg->route.url.host.c_str());

		routeStr = CSipMsgHelper::toStringRoute(pCtrlMsg->route);

		DEBUGV(m_psaid, "OUTGOING SIP MSG route after convert: %s\n", routeStr.c_str());
	}

	int ret = eXosip_message_build_request(&msg, "MESSAGE",
			CSipMsgHelper::toString(pCtrlMsg->to).c_str(),
			CSipMsgHelper::toString(pCtrlMsg->from).c_str(),
			(routeStr.length() > 0) ? routeStr.c_str(): NULL);

	if (OSIP_SUCCESS != ret)
	{
		psaPrint(m_psaid, "eXosip_message_build_request failed!\n");
		return FALSE;
	}
	if(1 == accessMode){
		osip_route_t *rt;
		osip_route_init(&rt);
		char * response = new char[128];

		if (osip_route_parse(rt,proxy.c_str()) != 0)
		{
			printf("Route does not parse!\n");
			return NULL;
		}
		else
		{
			osip_uri_uparam_add(rt->url,osip_strdup("lr"),NULL);
			osip_route_to_str(rt,&response);
		}

		osip_route_free(rt);
		osip_message_set_route(msg, response);
	}
	else if(2 == accessMode)
	{
		osip_route_t *rt;
		osip_route_init(&rt);
		char * response = new char[128];

		if (osip_route_parse(rt,proxy.c_str()) != 0)
		{
			printf("Route does not parse!\n");
			return NULL;
		}
		else
		{
			osip_uri_uparam_add(rt->url,osip_strdup("lr"),NULL);
			osip_route_to_str(rt,&response);
		}

		osip_route_free(rt);
		osip_message_set_route(msg, response);

		string url = "sip:";
		url.append(osip_from_get_url(msg->from)->username);
		url.append("@");
		url.append(osip_from_get_url(msg->from)->host);

		if(m_service_route.find(url) != m_service_route.end())
		{
			vector<char *> vec = m_service_route[url];
			vector<char*>::reverse_iterator it = vec.rbegin();
			while(it != vec.rend())
			{
				osip_message_set_route(msg, (*it));
				it++;
			}
		}
	}
	else{
		osip_route_t *rt;
		osip_route_init(&rt);
		string icscfAddr = (string)"<" + icscf + ";lr>";
		osip_message_set_route(msg, icscfAddr.c_str());
	}


	ExosipTranslator::convertMCF2CtrlMsg(pCtrlMsg, msg);

	ExosipTranslator::convertMCF2OsipMessage(*mcfMsg, msg);
		
	//add by liling 2010-7 to add ROUTE to out-going SIP MESSAGE
	char* buf = NULL;
	size_t len;
	osip_message_to_str(msg, &buf, &len);
	DEBUGV(m_psaid, "%s\n", buf);
	osip_free(buf);
		
	eXosip_lock();
	ret = eXosip_message_send_request(msg);
	eXosip_unlock();
	if (OSIP_SUCCESS != ret)
	{
		psaPrint(m_psaid, "Send MESSAGE failed!!!\n");
		return FALSE;
	}

	return TRUE;
}

void CExosipStack::storeDid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId, INT dialogId)
{
	CHAR* uniqueDialogId = new CHAR[512];
	memset(uniqueDialogId, 0, 512);
	__generateUniqueDialogId(uniqueDialogId, 512, from, to,	callId);

	this->m_map_dialogid.put(uniqueDialogId, dialogId);

	DEBUGV(m_psaid, "StoreDid: %s [%d]\n", uniqueDialogId, dialogId);

	delete[] uniqueDialogId;
}

void CExosipStack::storeCid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId, INT cid)
{
	CHAR* uniqueCallId = new CHAR[512];
	memset(uniqueCallId, 0, 512);
	__generateUniqueCallId(uniqueCallId, 512, from, to, callId);
	this->m_map_callid.put(uniqueCallId, cid);

	DEBUGV(m_psaid, "StoreCid: %s [%d]\n", uniqueCallId, cid);

	delete[] uniqueCallId;
}

void CExosipStack::removeDid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId)
{
	CHAR* uniqueDialogId = new CHAR[512];
		memset(uniqueDialogId, 0, 512);
	__generateUniqueDialogId(uniqueDialogId, 512, from, to, callId);

	this->m_map_dialogid.remove(uniqueDialogId);

	DEBUGV(m_psaid, "RmDid: %s\n", uniqueDialogId);

	delete[] uniqueDialogId;
}

void CExosipStack::removeCid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId)
{
	CHAR* uniqueCallId = new CHAR[512];
	memset(uniqueCallId, 0, 512);
	__generateUniqueCallId(uniqueCallId, 512, from, to, callId);
	this->m_map_callid.remove(uniqueCallId);

	DEBUGV(m_psaid, "RmCid: %s\n", uniqueCallId);

	delete[] uniqueCallId;
}

INT CExosipStack::getDid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId)
{
	INT did = -1;

	CHAR* uniqueDialogId = new CHAR[512];
	memset(uniqueDialogId, 0, 512);
	__generateUniqueDialogId(uniqueDialogId, 512, from, to, callId);

	if (FALSE == this->m_map_dialogid.get(uniqueDialogId, did))
	{
		did = -1;
	}

	delete[] uniqueDialogId;

	return did;
}

INT CExosipStack::getCid(RCTSipAddress from, RCTSipAddress to, RCTSipCallId callId)
{
	INT cid = -1;

	CHAR* uniqueCallId = new CHAR[512];
	memset(uniqueCallId, 0, 512);
	__generateUniqueCallId(uniqueCallId, 512, from, to, callId);

	if (FALSE == this->m_map_callid.get(uniqueCallId, cid))
	{
		cid = -1;
	}

	delete[] uniqueCallId;

	return cid;
}

bool CExosipStack::isConfCall(string username)
{

	printf("isConfCall username :%s\n", username.c_str());
	if(confType == ""){
		return false;
	}
	printf("isConfCall: %s\n", confType.c_str());

	if(confType == "XXX" && username.size() == confType.size()){
		if(username.compare("000") >= 0
				&& username.compare("999") <= 0){
			return true;
		}
	}
	else if(confType == username){
		return true;
	}

	return false;
}


