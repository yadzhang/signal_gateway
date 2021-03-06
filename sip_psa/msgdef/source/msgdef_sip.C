/*****************************************************************************
 * msgdef_sip.C
 * It is an implementation file of message definition.
 * 
 * Note: This file is created automatically by msg compiler tool. 
 *       Please do not modify it.
 * 
 * Created at Tue Feb 21 11:46:04 2012
.
 * 
 ******************************************************************************/
#include "msgdef_sip.h"
#include "info.h"


/////////////////////////////////////////////
//           for class TSipCtrlMsg
/////////////////////////////////////////////
PTCtrlMsg TSipCtrlMsg::clone()
{
	PTSipCtrlMsg amsg = new TSipCtrlMsg();
	amsg->optionSet                 = optionSet;

	amsg->orgAddr                   = orgAddr;

	amsg->sip_callId                = sip_callId;
	amsg->from                      = from;
	amsg->to                        = to;
	amsg->cseq_method               = cseq_method;
	amsg->cseq_number               = cseq_number;
	amsg->via                    = via;
	amsg->route                     = route;
	return amsg;
}
TSipCtrlMsg& TSipCtrlMsg::operator=(const TSipCtrlMsg &r)
{
	sip_callId                = r.sip_callId;
	from                      = r.from;
	to                        = r.to;
	cseq_method               = r.cseq_method;
	cseq_number               = r.cseq_number;
	via                    = r.via;
	route                     = r.route;
	return *this;
}

BOOL TSipCtrlMsg::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipCtrlMsg,msg)

	COMPARE_FORCE_NEST(TSipCtrlMsg,TSipCallId,sip_callId)
	COMPARE_FORCE_NEST(TSipCtrlMsg,TSipAddress,from)
	COMPARE_FORCE_NEST(TSipCtrlMsg,TSipAddress,to)
	COMPARE_FORCE_VCHAR(TSipCtrlMsg,cseq_method)
	COMPARE_FORCE_VCHAR(TSipCtrlMsg,cseq_number)
	COMPARE_FORCE_NEST(TSipCtrlMsg,TSipURI, via)
	COMPARE_FORCE_NEST(TSipCtrlMsg,TSipAddress,route)

	COMPARE_END
}

INT TSipCtrlMsg::size()
{
	INT tmpSize = 0;

	tmpSize += sizeof(UINT); //for optionSet

	if( optionSet & orgAddr_flag )	tmpSize += orgAddr.size();

	tmpSize += sip_callId.size();
	tmpSize += from.size();
	tmpSize += to.size();
	tmpSize += cseq_method.size();
	tmpSize += cseq_number.size();
	tmpSize += via.size();
	tmpSize += route.size();

	return tmpSize;
}

INT TSipCtrlMsg::encode(CHAR* &buf)
{
	ENCODE_INT( buf , optionSet )

	if( optionSet & orgAddr_flag )	orgAddr.encode(buf);

	sip_callId.encode(buf);
	from.encode(buf);
	to.encode(buf);
	cseq_method.encode(buf);
	cseq_number.encode(buf);
	via.encode(buf);
	route.encode(buf);

	return size();
}

INT TSipCtrlMsg::decode(CHAR* &buf)
{
	DECODE_INT( optionSet , buf )

	if( optionSet & orgAddr_flag )	orgAddr.decode(buf);

	sip_callId.decode(buf);
	from.decode(buf);
	to.decode(buf);
	cseq_method.decode(buf);
	cseq_number.decode(buf);
	via.decode(buf);
	route.decode(buf);

	return size();
}

BOOL TSipCtrlMsg::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipCtrlMsg,TSipCallId,sip_callId)
	FILL_FORCE_NEST(TSipCtrlMsg,TSipAddress,from)
	FILL_FORCE_NEST(TSipCtrlMsg,TSipAddress,to)
	FILL_FORCE_VCHAR(TSipCtrlMsg,cseq_method)
	FILL_FORCE_VCHAR(TSipCtrlMsg,cseq_number)
	FILL_FORCE_NEST(TSipCtrlMsg, TSipVia ,via)
	FILL_FORCE_NEST(TSipCtrlMsg,TSipAddress,route)

	FILL_FIELD_END
}

void TSipCtrlMsg::print(ostrstream& st)
{
	st<<"==| TSipCtrlMsg =="<<endl;
	CHAR temp[30];
	sprintf(temp,"0x%x",optionSet);
	st<<"optionSet                    = "<<temp<<endl;

	if( optionSet & orgAddr_flag )
	{
		st<<"orgAddr : ";
		orgAddr.print(st);
	}
	else
		st<<"orgAddr                      = (not present)"<<endl;

	st<<"$sip_callId : ";
	sip_callId.print(st);
	st<<"$from : ";
	from.print(st);
	st<<"$to : ";
	to.print(st);
	st<<"$cseq_method                 = "<<cseq_method.GetVarCharContentPoint()<<endl;
	st<<"$cseq_number                 = "<<cseq_number.GetVarCharContentPoint()<<endl;
	st<<"$via:"<<endl;
	via.print(st);
	st<<"$route : ";
	route.print(st);

}

/////////////////////////////////////////////
//           for class TSipResp
/////////////////////////////////////////////
PTMsgBody TSipResp::clone()
{
	PTSipResp amsg = new TSipResp();
	amsg->statusCode                = statusCode;
	amsg->reason_phase              = reason_phase;
	amsg->expires                   = expires;
	amsg->contact                   = contact;
	amsg->sip_etag                  = sip_etag;
	amsg->content_type              = content_type;
	amsg->authScheme                = authScheme;
	amsg->authRealm                 = authRealm;
	amsg->authNonce                 = authNonce;
	amsg->authStale                 = authStale;
	amsg->authAlgor                 = authAlgor;
	amsg->authQop                   = authQop;
	amsg->authOpaque                = authOpaque;
	amsg->body                      = body;
	return amsg;
}
TSipResp& TSipResp::operator=(const TSipResp &r)
{
	statusCode                = r.statusCode;
	reason_phase              = r.reason_phase;
	expires                   = r.expires;
	contact                   = r.contact;
	sip_etag                  = r.sip_etag;
	content_type              = r.content_type;
	authScheme                = r.authScheme;
	authRealm                 = r.authRealm;
	authNonce                 = r.authNonce;
	authStale                 = r.authStale;
	authAlgor                 = r.authAlgor;
	authQop                   = r.authQop;
	authOpaque                = r.authOpaque;
	body                      = r.body;
	return *this;
}

BOOL TSipResp::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipResp,msg)

	COMPARE_FORCE_INT(TSipResp,statusCode)
	COMPARE_FORCE_VCHAR(TSipResp,reason_phase)
	COMPARE_FORCE_INT(TSipResp,expires)
	COMPARE_FORCE_NEST(TSipResp,TSipAddress,contact)
	COMPARE_FORCE_VCHAR(TSipResp,sip_etag)
	COMPARE_FORCE_NEST(TSipResp,TSipContentType,content_type)
	COMPARE_FORCE_VCHAR(TSipResp,authScheme)
	COMPARE_FORCE_VCHAR(TSipResp,authRealm)
	COMPARE_FORCE_VCHAR(TSipResp,authNonce)
	COMPARE_FORCE_VCHAR(TSipResp,authStale)
	COMPARE_FORCE_VCHAR(TSipResp,authAlgor)
	COMPARE_FORCE_VCHAR(TSipResp,authQop)
	COMPARE_FORCE_VCHAR(TSipResp,authOpaque)
	COMPARE_FORCE_NEST(TSipResp,TSipBody,body)

	COMPARE_END
}

INT TSipResp::size()
{
	INT tmpSize = 0;

	tmpSize += sizeof(INT);
	tmpSize += reason_phase.size();
	tmpSize += sizeof(INT);
	tmpSize += contact.size();
	tmpSize += sip_etag.size();
	tmpSize += content_type.size();
	tmpSize += authScheme.size();
	tmpSize += authRealm.size();
	tmpSize += authNonce.size();
	tmpSize += authStale.size();
	tmpSize += authAlgor.size();
	tmpSize += authQop.size();
	tmpSize += authOpaque.size();
	tmpSize += body.size();

	return tmpSize;
}

INT TSipResp::encode(CHAR* &buf)
{
	ENCODE_INT( buf , statusCode )
	reason_phase.encode(buf);
	ENCODE_INT( buf , expires )
	contact.encode(buf);
	sip_etag.encode(buf);
	content_type.encode(buf);
	authScheme.encode(buf);
	authRealm.encode(buf);
	authNonce.encode(buf);
	authStale.encode(buf);
	authAlgor.encode(buf);
	authQop.encode(buf);
	authOpaque.encode(buf);
	body.encode(buf);

	return size();
}

INT TSipResp::decode(CHAR* &buf)
{
	DECODE_INT( statusCode, buf )
	reason_phase.decode(buf);
	DECODE_INT( expires, buf )
	contact.decode(buf);
	sip_etag.decode(buf);
	content_type.decode(buf);
	authScheme.decode(buf);
	authRealm.decode(buf);
	authNonce.decode(buf);
	authStale.decode(buf);
	authAlgor.decode(buf);
	authQop.decode(buf);
	authOpaque.decode(buf);
	body.decode(buf);

	return size();
}

BOOL TSipResp::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_INT(TSipResp,statusCode)
	FILL_FORCE_VCHAR(TSipResp,reason_phase)
	FILL_FORCE_INT(TSipResp,expires)
	FILL_FORCE_NEST(TSipResp,TSipAddress,contact)
	FILL_FORCE_VCHAR(TSipResp,sip_etag)
	FILL_FORCE_NEST(TSipResp,TSipContentType,content_type)
	FILL_FORCE_VCHAR(TSipResp,authScheme)
	FILL_FORCE_VCHAR(TSipResp,authRealm)
	FILL_FORCE_VCHAR(TSipResp,authNonce)
	FILL_FORCE_VCHAR(TSipResp,authStale)
	FILL_FORCE_VCHAR(TSipResp,authAlgor)
	FILL_FORCE_VCHAR(TSipResp,authQop)
	FILL_FORCE_VCHAR(TSipResp,authOpaque)
	FILL_FORCE_NEST(TSipResp,TSipBody,body)

	FILL_FIELD_END
}

void TSipResp::print(ostrstream& st)
{
	st<<"==| TSipResp =="<<endl;
	st<<"$statusCode                  = "<<statusCode<<endl;
	st<<"$reason_phase                = "<<reason_phase.GetVarCharContentPoint()<<endl;
	st<<"$expires                     = "<<expires<<endl;
	st<<"$contact : ";
	contact.print(st);
	st<<"$sip_etag                    = "<<sip_etag.GetVarCharContentPoint()<<endl;
	st<<"$content_type : ";
	content_type.print(st);
	st<<"$authScheme                  = "<<authScheme.GetVarCharContentPoint()<<endl;
	st<<"$authRealm                   = "<<authRealm.GetVarCharContentPoint()<<endl;
	st<<"$authNonce                   = "<<authNonce.GetVarCharContentPoint()<<endl;
	st<<"$authStale                   = "<<authStale.GetVarCharContentPoint()<<endl;
	st<<"$authAlgor                   = "<<authAlgor.GetVarCharContentPoint()<<endl;
	st<<"$authQop                     = "<<authQop.GetVarCharContentPoint()<<endl;
	st<<"$authOpaque                  = "<<authOpaque.GetVarCharContentPoint()<<endl;
	st<<"$body : ";
	body.print(st);

}

/////////////////////////////////////////////
//           for class TSipReq
/////////////////////////////////////////////
PTMsgBody TSipReq::clone()
{
	PTSipReq amsg = new TSipReq();
	amsg->req_uri                   = req_uri;
	amsg->content_type				= content_type;
	amsg->body						= body;
	return amsg;
}
TSipReq& TSipReq::operator=(const TSipReq &r)
{
	req_uri                   = r.req_uri;
	content_type			  = r.content_type;
	body					  = r.body;
	return *this;
}

BOOL TSipReq::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipReq,msg)

	COMPARE_FORCE_NEST(TSipReq,TSipURI,req_uri)
	COMPARE_FORCE_NEST(TSipReq,TSipContentType,content_type)
	COMPARE_FORCE_NEST(TSipReq,TSipBody,body)

	COMPARE_END
}

INT TSipReq::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();
	tmpSize += content_type.size();
	tmpSize += body.size();

	return tmpSize;
}

INT TSipReq::encode(CHAR* &buf)
{
	req_uri.encode(buf);
	content_type.encode(buf);
	body.encode(buf);

	return size();
}

INT TSipReq::decode(CHAR* &buf)
{
	req_uri.decode(buf);
	content_type.decode(buf);
	body.decode(buf);

	return size();
}

BOOL TSipReq::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipReq,TSipURI,req_uri)
	FILL_FORCE_NEST(TSipReq, TSipContentType, content_type)
	FILL_FORCE_NEST(TSipReq, TSipBody, body);

	FILL_FIELD_END
}

void TSipReq::print(ostrstream& st)
{
	st<<"==| TSipReq =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);

	st<<"++| TSipBody =="<<endl;
	st<<"content_type: ";
	content_type.print(st);
	st<<"body: ";
	body.print(st);


}

/////////////////////////////////////////////
//           for class TSipBye
/////////////////////////////////////////////
PTMsgBody TSipBye::clone()
{
	PTSipBye amsg = new TSipBye();
	amsg->req_uri                   = req_uri;
	return amsg;
}
TSipBye& TSipBye::operator=(const TSipBye &r)
{
	req_uri                   = r.req_uri;
	return *this;
}

BOOL TSipBye::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipBye,msg)

	COMPARE_FORCE_NEST(TSipBye,TSipURI,req_uri)

	COMPARE_END
}

INT TSipBye::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();

	return tmpSize;
}

INT TSipBye::encode(CHAR* &buf)
{
	req_uri.encode(buf);

	return size();
}

INT TSipBye::decode(CHAR* &buf)
{
	req_uri.decode(buf);

	return size();
}

BOOL TSipBye::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipBye,TSipURI,req_uri)

	FILL_FIELD_END
}

void TSipBye::print(ostrstream& st)
{
	st<<"==| TSipBye =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);

}

/////////////////////////////////////////////
//           for class TSipCancel
/////////////////////////////////////////////
PTMsgBody TSipCancel::clone()
{
	PTSipCancel amsg = new TSipCancel();
	amsg->req_uri                   = req_uri;
	return amsg;
}
TSipCancel& TSipCancel::operator=(const TSipCancel &r)
{
	req_uri                   = r.req_uri;
	return *this;
}

BOOL TSipCancel::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipCancel,msg)

	COMPARE_FORCE_NEST(TSipCancel,TSipURI,req_uri)

	COMPARE_END
}

INT TSipCancel::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();

	return tmpSize;
}

INT TSipCancel::encode(CHAR* &buf)
{
	req_uri.encode(buf);

	return size();
}

INT TSipCancel::decode(CHAR* &buf)
{
	req_uri.decode(buf);

	return size();
}

BOOL TSipCancel::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipCancel,TSipURI,req_uri)

	FILL_FIELD_END
}

void TSipCancel::print(ostrstream& st)
{
	st<<"==| TSipCancel =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);

}

/////////////////////////////////////////////
//           for class TSipRegister
/////////////////////////////////////////////
PTMsgBody TSipRegister::clone()
{
	PTSipRegister amsg = new TSipRegister();
	amsg->req_uri                   = req_uri;
	amsg->contact                   = contact;
	amsg->expires                   = expires;
	amsg->authScheme                = authScheme;
	amsg->authUserName              = authUserName;
	amsg->authRealm                 = authRealm;
	amsg->authNonce                 = authNonce;
	amsg->authUri                   = authUri;
	amsg->authResponse              = authResponse;
	amsg->authAlgor                 = authAlgor;
	amsg->authCnonce                = authCnonce;
	amsg->authOpaque                = authOpaque;
	amsg->authQop                   = authQop;
	amsg->authNc                    = authNc;
	return amsg;
}
TSipRegister& TSipRegister::operator=(const TSipRegister &r)
{
	req_uri                   = r.req_uri;
	contact                   = r.contact;
	expires                   = r.expires;
	authScheme                = r.authScheme;
	authUserName              = r.authUserName;
	authRealm                 = r.authRealm;
	authNonce                 = r.authNonce;
	authUri                   = r.authUri;
	authResponse              = r.authResponse;
	authAlgor                 = r.authAlgor;
	authCnonce                = r.authCnonce;
	authOpaque                = r.authOpaque;
	authQop                   = r.authQop;
	authNc                    = r.authNc;
	return *this;
}

BOOL TSipRegister::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipRegister,msg)

	COMPARE_FORCE_NEST(TSipRegister,TSipURI,req_uri)
	COMPARE_FORCE_NEST(TSipRegister,TSipAddress,contact)
	COMPARE_FORCE_INT(TSipRegister,expires)
	COMPARE_FORCE_VCHAR(TSipRegister,authScheme)
	COMPARE_FORCE_VCHAR(TSipRegister,authUserName)
	COMPARE_FORCE_VCHAR(TSipRegister,authRealm)
	COMPARE_FORCE_VCHAR(TSipRegister,authNonce)
	COMPARE_FORCE_VCHAR(TSipRegister,authUri)
	COMPARE_FORCE_VCHAR(TSipRegister,authResponse)
	COMPARE_FORCE_VCHAR(TSipRegister,authAlgor)
	COMPARE_FORCE_VCHAR(TSipRegister,authCnonce)
	COMPARE_FORCE_VCHAR(TSipRegister,authOpaque)
	COMPARE_FORCE_VCHAR(TSipRegister,authQop)
	COMPARE_FORCE_VCHAR(TSipRegister,authNc)

	COMPARE_END
}

INT TSipRegister::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();
	tmpSize += contact.size();
	tmpSize += sizeof(INT);
	tmpSize += authScheme.size();
	tmpSize += authUserName.size();
	tmpSize += authRealm.size();
	tmpSize += authNonce.size();
	tmpSize += authUri.size();
	tmpSize += authResponse.size();
	tmpSize += authAlgor.size();
	tmpSize += authCnonce.size();
	tmpSize += authOpaque.size();
	tmpSize += authQop.size();
	tmpSize += authNc.size();

	return tmpSize;
}

INT TSipRegister::encode(CHAR* &buf)
{
	req_uri.encode(buf);
	contact.encode(buf);
	ENCODE_INT( buf , expires )
	authScheme.encode(buf);
	authUserName.encode(buf);
	authRealm.encode(buf);
	authNonce.encode(buf);
	authUri.encode(buf);
	authResponse.encode(buf);
	authAlgor.encode(buf);
	authCnonce.encode(buf);
	authOpaque.encode(buf);
	authQop.encode(buf);
	authNc.encode(buf);

	return size();
}

INT TSipRegister::decode(CHAR* &buf)
{
	req_uri.decode(buf);
	contact.decode(buf);
	DECODE_INT( expires, buf )
	authScheme.decode(buf);
	authUserName.decode(buf);
	authRealm.decode(buf);
	authNonce.decode(buf);
	authUri.decode(buf);
	authResponse.decode(buf);
	authAlgor.decode(buf);
	authCnonce.decode(buf);
	authOpaque.decode(buf);
	authQop.decode(buf);
	authNc.decode(buf);

	return size();
}

BOOL TSipRegister::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipRegister,TSipURI,req_uri)
	FILL_FORCE_NEST(TSipRegister,TSipAddress,contact)
	FILL_FORCE_INT(TSipRegister,expires)
	FILL_FORCE_VCHAR(TSipRegister,authScheme)
	FILL_FORCE_VCHAR(TSipRegister,authUserName)
	FILL_FORCE_VCHAR(TSipRegister,authRealm)
	FILL_FORCE_VCHAR(TSipRegister,authNonce)
	FILL_FORCE_VCHAR(TSipRegister,authUri)
	FILL_FORCE_VCHAR(TSipRegister,authResponse)
	FILL_FORCE_VCHAR(TSipRegister,authAlgor)
	FILL_FORCE_VCHAR(TSipRegister,authCnonce)
	FILL_FORCE_VCHAR(TSipRegister,authOpaque)
	FILL_FORCE_VCHAR(TSipRegister,authQop)
	FILL_FORCE_VCHAR(TSipRegister,authNc)

	FILL_FIELD_END
}

void TSipRegister::print(ostrstream& st)
{
	st<<"==| TSipRegister =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);
	st<<"$contact : ";
	contact.print(st);
	st<<"$expires                     = "<<expires<<endl;
	st<<"$authScheme                  = "<<authScheme.GetVarCharContentPoint()<<endl;
	st<<"$authUserName                = "<<authUserName.GetVarCharContentPoint()<<endl;
	st<<"$authRealm                   = "<<authRealm.GetVarCharContentPoint()<<endl;
	st<<"$authNonce                   = "<<authNonce.GetVarCharContentPoint()<<endl;
	st<<"$authUri                     = "<<authUri.GetVarCharContentPoint()<<endl;
	st<<"$authResponse                = "<<authResponse.GetVarCharContentPoint()<<endl;
	st<<"$authAlgor                   = "<<authAlgor.GetVarCharContentPoint()<<endl;
	st<<"$authCnonce                  = "<<authCnonce.GetVarCharContentPoint()<<endl;
	st<<"$authOpaque                  = "<<authOpaque.GetVarCharContentPoint()<<endl;
	st<<"$authQop                     = "<<authQop.GetVarCharContentPoint()<<endl;
	st<<"$authNc                      = "<<authNc.GetVarCharContentPoint()<<endl;

}

/////////////////////////////////////////////
//           for class TSipInvite
/////////////////////////////////////////////
PTMsgBody TSipInvite::clone()
{
	PTSipInvite amsg = new TSipInvite();
	amsg->req_uri                   = req_uri;
	amsg->content_type              = content_type;
	amsg->body                      = body;
	return amsg;
}
TSipInvite& TSipInvite::operator=(const TSipInvite &r)
{
	req_uri                   = r.req_uri;
	content_type              = r.content_type;
	body                      = r.body;
	return *this;
}

BOOL TSipInvite::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipInvite,msg)

	COMPARE_FORCE_NEST(TSipInvite,TSipURI,req_uri)
	COMPARE_FORCE_NEST(TSipInvite,TSipContentType,content_type)
	COMPARE_FORCE_NEST(TSipInvite,TSipBody,body)

	COMPARE_END
}

INT TSipInvite::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();
	tmpSize += content_type.size();
	tmpSize += body.size();

	return tmpSize;
}

INT TSipInvite::encode(CHAR* &buf)
{
	req_uri.encode(buf);
	content_type.encode(buf);
	body.encode(buf);

	return size();
}

INT TSipInvite::decode(CHAR* &buf)
{
	req_uri.decode(buf);
	content_type.decode(buf);
	body.decode(buf);

	return size();
}

BOOL TSipInvite::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipInvite,TSipURI,req_uri)
	FILL_FORCE_NEST(TSipInvite,TSipContentType,content_type)
	FILL_FORCE_NEST(TSipInvite,TSipBody,body)

	FILL_FIELD_END
}

void TSipInvite::print(ostrstream& st)
{
	st<<"==| TSipInvite =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);
	st<<"$content_type : ";
	content_type.print(st);
	st<<"$body : ";
	body.print(st);

}

/////////////////////////////////////////////
//           for class TSipMessage
/////////////////////////////////////////////
PTMsgBody TSipMessage::clone()
{
	PTSipMessage amsg = new TSipMessage();
	amsg->req_uri                   = req_uri;
	amsg->content_type              = content_type;
	amsg->body                      = body;
	return amsg;
}
TSipMessage& TSipMessage::operator=(const TSipMessage &r)
{
	req_uri                   = r.req_uri;
	content_type              = r.content_type;
	body                      = r.body;
	return *this;
}

BOOL TSipMessage::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipMessage,msg)

	COMPARE_FORCE_NEST(TSipMessage,TSipURI,req_uri)
	COMPARE_FORCE_NEST(TSipMessage,TSipContentType,content_type)
	COMPARE_FORCE_NEST(TSipMessage,TSipBody,body)

	COMPARE_END
}

INT TSipMessage::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();
	tmpSize += content_type.size();
	tmpSize += body.size();

	return tmpSize;
}

INT TSipMessage::encode(CHAR* &buf)
{
	req_uri.encode(buf);
	content_type.encode(buf);
	body.encode(buf);

	return size();
}

INT TSipMessage::decode(CHAR* &buf)
{
	req_uri.decode(buf);
	content_type.decode(buf);
	body.decode(buf);

	return size();
}

BOOL TSipMessage::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipMessage,TSipURI,req_uri)
	FILL_FORCE_NEST(TSipMessage,TSipContentType,content_type)
	FILL_FORCE_NEST(TSipMessage,TSipBody,body)

	FILL_FIELD_END
}

void TSipMessage::print(ostrstream& st)
{
	st<<"==| TSipMessage =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);
	st<<"$content_type : ";
	content_type.print(st);
	st<<"$body : ";
	body.print(st);

}

/////////////////////////////////////////////
//           for class TSipInfo
/////////////////////////////////////////////
PTMsgBody TSipInfo::clone()
{
	PTSipInfo amsg = new TSipInfo();
	amsg->req_uri                   = req_uri;
	amsg->content_type              = content_type;
	amsg->body                      = body;
	return amsg;
}
TSipInfo& TSipInfo::operator=(const TSipInfo &r)
{
	req_uri                   = r.req_uri;
	content_type              = r.content_type;
	body                      = r.body;
	return *this;
}

BOOL TSipInfo::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipInfo,msg)

	COMPARE_FORCE_NEST(TSipInfo,TSipURI,req_uri)
	COMPARE_FORCE_NEST(TSipInfo,TSipContentType,content_type)
	COMPARE_FORCE_NEST(TSipInfo,TSipBody,body)

	COMPARE_END
}

INT TSipInfo::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();
	tmpSize += content_type.size();
	tmpSize += body.size();

	return tmpSize;
}

INT TSipInfo::encode(CHAR* &buf)
{
	req_uri.encode(buf);
	content_type.encode(buf);
	body.encode(buf);

	return size();
}

INT TSipInfo::decode(CHAR* &buf)
{
	req_uri.decode(buf);
	content_type.decode(buf);
	body.decode(buf);

	return size();
}

BOOL TSipInfo::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipInfo,TSipURI,req_uri)
	FILL_FORCE_NEST(TSipInfo,TSipContentType,content_type)
	FILL_FORCE_NEST(TSipInfo,TSipBody,body)

	FILL_FIELD_END
}

void TSipInfo::print(ostrstream& st)
{
	st<<"==| TSipInfo =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);
	st<<"$content_type : ";
	content_type.print(st);
	st<<"$body : ";
	body.print(st);

}



/////////////////////////////////////////////
//           for class TSipUpdate
/////////////////////////////////////////////
PTMsgBody TSipUpdate::clone()
{
	PTSipInfo amsg = new TSipInfo();
	amsg->req_uri                   = req_uri;
	amsg->content_type              = content_type;
	amsg->body                      = body;
	return amsg;
}
TSipInfo& TSipUpdate::operator=(const TSipInfo &r)
{
	req_uri                   = r.req_uri;
	content_type              = r.content_type;
	body                      = r.body;
	return *this;
}

BOOL TSipUpdate::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipInfo,msg)

	COMPARE_FORCE_NEST(TSipUpdate,TSipURI,req_uri)
	COMPARE_FORCE_NEST(TSipUpdate,TSipContentType,content_type)
	COMPARE_FORCE_NEST(TSipUpdate,TSipBody,body)

	COMPARE_END
}

INT TSipUpdate::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();
	tmpSize += content_type.size();
	tmpSize += body.size();

	return tmpSize;
}

INT TSipUpdate::encode(CHAR* &buf)
{
	req_uri.encode(buf);
	content_type.encode(buf);
	body.encode(buf);

	return size();
}

INT TSipUpdate::decode(CHAR* &buf)
{
	req_uri.decode(buf);
	content_type.decode(buf);
	body.decode(buf);

	return size();
}

BOOL TSipUpdate::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipUpdate,TSipURI,req_uri)
	FILL_FORCE_NEST(TSipUpdate,TSipContentType,content_type)
	FILL_FORCE_NEST(TSipUpdate,TSipBody,body)

	FILL_FIELD_END
}

void TSipUpdate::print(ostrstream& st)
{
	st<<"==| TSipUpdate =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);
	st<<"$content_type : ";
	content_type.print(st);
	st<<"$body : ";
	body.print(st);

}


/////////////////////////////////////////////
//           for class TSipPublish
/////////////////////////////////////////////
PTMsgBody TSipPublish::clone()
{
	PTSipPublish amsg = new TSipPublish();
	amsg->req_uri                   = req_uri;
	amsg->expires                   = expires;
	amsg->sip_if_match              = sip_if_match;
	amsg->event_type                = event_type;
	amsg->content_type              = content_type;
	amsg->body                      = body;
	return amsg;
}
TSipPublish& TSipPublish::operator=(const TSipPublish &r)
{
	req_uri                   = r.req_uri;
	expires                   = r.expires;
	sip_if_match              = r.sip_if_match;
	event_type                = r.event_type;
	content_type              = r.content_type;
	body                      = r.body;
	return *this;
}

BOOL TSipPublish::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipPublish,msg)

	COMPARE_FORCE_NEST(TSipPublish,TSipURI,req_uri)
	COMPARE_FORCE_INT(TSipPublish,expires)
	COMPARE_FORCE_VCHAR(TSipPublish,sip_if_match)
	COMPARE_FORCE_VCHAR(TSipPublish,event_type)
	COMPARE_FORCE_NEST(TSipPublish,TSipContentType,content_type)
	COMPARE_FORCE_NEST(TSipPublish,TSipBody,body)

	COMPARE_END
}

INT TSipPublish::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();
	tmpSize += sizeof(INT);
	tmpSize += sip_if_match.size();
	tmpSize += event_type.size();
	tmpSize += content_type.size();
	tmpSize += body.size();

	return tmpSize;
}

INT TSipPublish::encode(CHAR* &buf)
{
	req_uri.encode(buf);
	ENCODE_INT( buf , expires )
	sip_if_match.encode(buf);
	event_type.encode(buf);
	content_type.encode(buf);
	body.encode(buf);

	return size();
}

INT TSipPublish::decode(CHAR* &buf)
{
	req_uri.decode(buf);
	DECODE_INT( expires, buf )
	sip_if_match.decode(buf);
	event_type.decode(buf);
	content_type.decode(buf);
	body.decode(buf);

	return size();
}

BOOL TSipPublish::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipPublish,TSipURI,req_uri)
	FILL_FORCE_INT(TSipPublish,expires)
	FILL_FORCE_VCHAR(TSipPublish,sip_if_match)
	FILL_FORCE_VCHAR(TSipPublish,event_type)
	FILL_FORCE_NEST(TSipPublish,TSipContentType,content_type)
	FILL_FORCE_NEST(TSipPublish,TSipBody,body)

	FILL_FIELD_END
}

void TSipPublish::print(ostrstream& st)
{
	st<<"==| TSipPublish =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);
	st<<"$expires                     = "<<expires<<endl;
	st<<"$sip_if_match                = "<<sip_if_match.GetVarCharContentPoint()<<endl;
	st<<"$event_type                  = "<<event_type.GetVarCharContentPoint()<<endl;
	st<<"$content_type : ";
	content_type.print(st);
	st<<"$body : ";
	body.print(st);

}

/////////////////////////////////////////////
//           for class TSipSubscribe
/////////////////////////////////////////////
PTMsgBody TSipSubscribe::clone()
{
	PTSipSubscribe amsg = new TSipSubscribe();
	amsg->req_uri                   = req_uri;
	amsg->expires                   = expires;
	amsg->event_type                = event_type;
	amsg->content_type              = content_type;
	amsg->body                      = body;
	return amsg;
}
TSipSubscribe& TSipSubscribe::operator=(const TSipSubscribe &r)
{
	req_uri                   = r.req_uri;
	expires                   = r.expires;
	event_type                = r.event_type;
	content_type              = r.content_type;
	body                      = r.body;
	return *this;
}

BOOL TSipSubscribe::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipSubscribe,msg)

	COMPARE_FORCE_NEST(TSipSubscribe,TSipURI,req_uri)
	COMPARE_FORCE_INT(TSipSubscribe,expires)
	COMPARE_FORCE_VCHAR(TSipSubscribe,event_type)
	COMPARE_FORCE_NEST(TSipSubscribe,TSipContentType,content_type)
	COMPARE_FORCE_NEST(TSipSubscribe,TSipBody,body)

	COMPARE_END
}

INT TSipSubscribe::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();
	tmpSize += sizeof(INT);
	tmpSize += event_type.size();
	tmpSize += content_type.size();
	tmpSize += body.size();

	return tmpSize;
}

INT TSipSubscribe::encode(CHAR* &buf)
{
	req_uri.encode(buf);
	ENCODE_INT( buf , expires )
	event_type.encode(buf);
	content_type.encode(buf);
	body.encode(buf);

	return size();
}

INT TSipSubscribe::decode(CHAR* &buf)
{
	req_uri.decode(buf);
	DECODE_INT( expires, buf )
	event_type.decode(buf);
	content_type.decode(buf);
	body.decode(buf);

	return size();
}

BOOL TSipSubscribe::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipSubscribe,TSipURI,req_uri)
	FILL_FORCE_INT(TSipSubscribe,expires)
	FILL_FORCE_VCHAR(TSipSubscribe,event_type)
	FILL_FORCE_NEST(TSipSubscribe,TSipContentType,content_type)
	FILL_FORCE_NEST(TSipSubscribe,TSipBody,body)

	FILL_FIELD_END
}

void TSipSubscribe::print(ostrstream& st)
{
	st<<"==| TSipSubscribe =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);
	st<<"$expires                     = "<<expires<<endl;
	st<<"$event_type                  = "<<event_type.GetVarCharContentPoint()<<endl;
	st<<"$content_type : ";
	content_type.print(st);
	st<<"$body : ";
	body.print(st);

}

/////////////////////////////////////////////
//           for class TSipNotify
/////////////////////////////////////////////
PTMsgBody TSipNotify::clone()
{
	PTSipNotify amsg = new TSipNotify();
	amsg->req_uri                   = req_uri;
	amsg->event_type                = event_type;
	amsg->subscription_state        = subscription_state;
	amsg->content_type              = content_type;
	amsg->body                      = body;
	return amsg;
}
TSipNotify& TSipNotify::operator=(const TSipNotify &r)
{
	req_uri                   = r.req_uri;
	event_type                = r.event_type;
	subscription_state        = r.subscription_state;
	content_type              = r.content_type;
	body                      = r.body;
	return *this;
}

BOOL TSipNotify::operator == (TMsgPara& msg)
{
	COMPARE_MSG_BEGIN(TSipNotify,msg)

	COMPARE_FORCE_NEST(TSipNotify,TSipURI,req_uri)
	COMPARE_FORCE_VCHAR(TSipNotify,event_type)
	COMPARE_FORCE_NEST(TSipNotify,TSipSubscriptionState,subscription_state)
	COMPARE_FORCE_NEST(TSipNotify,TSipContentType,content_type)
	COMPARE_FORCE_NEST(TSipNotify,TSipBody,body)

	COMPARE_END
}

INT TSipNotify::size()
{
	INT tmpSize = 0;

	tmpSize += req_uri.size();
	tmpSize += event_type.size();
	tmpSize += subscription_state.size();
	tmpSize += content_type.size();
	tmpSize += body.size();

	return tmpSize;
}

INT TSipNotify::encode(CHAR* &buf)
{
	req_uri.encode(buf);
	event_type.encode(buf);
	subscription_state.encode(buf);
	content_type.encode(buf);
	body.encode(buf);

	return size();
}

INT TSipNotify::decode(CHAR* &buf)
{
	req_uri.decode(buf);
	event_type.decode(buf);
	subscription_state.decode(buf);
	content_type.decode(buf);
	body.decode(buf);

	return size();
}

BOOL TSipNotify::decodeFromXML(TiXmlHandle& xmlParser,PCGFSM fsm)
{
	FILL_FIELD_BEGIN

	FILL_FORCE_NEST(TSipNotify,TSipURI,req_uri)
	FILL_FORCE_VCHAR(TSipNotify,event_type)
	FILL_FORCE_NEST(TSipNotify,TSipSubscriptionState,subscription_state)
	FILL_FORCE_NEST(TSipNotify,TSipContentType,content_type)
	FILL_FORCE_NEST(TSipNotify,TSipBody,body)

	FILL_FIELD_END
}

void TSipNotify::print(ostrstream& st)
{
	st<<"==| TSipNotify =="<<endl;
	st<<"$req_uri : ";
	req_uri.print(st);
	st<<"$event_type                  = "<<event_type.GetVarCharContentPoint()<<endl;
	st<<"$subscription_state : ";
	subscription_state.print(st);
	st<<"$content_type : ";
	content_type.print(st);
	st<<"$body : ";
	body.print(st);

}
