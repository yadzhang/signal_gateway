/*
 * ex: set ro:
 * DO NOT EDIT.
 * generated by smc (http://smc.sourceforge.net/)
 * from file : CSipCallModule_sm.sm
 */


/*********************************************************************
 * Copyright (c)2010-2012, by BUPT
 * All rights reserved.

 * FileName:       CSipCallModule.sm
 * System:         webrtc
 * SubSystem:      gateway
 * Author:         Liu Mingshuan
 * Date:           2012.11.28
 * Version:        1.0
 * Description:
     SipCallModule state machineã

 *
 * Last Modified:
     2013-4-17 add Default state
            By Liu Mingshuan.
*******************************************************************************/


#include "CSipCallModule.h"
#include "./CSipCallModule_sm.h"

using namespace statemap;

// Static class declarations.
CSipCallModState_IDLE CSipCallModState::IDLE("CSipCallModState::IDLE", 0);
CSipCallModState_CALLPROC CSipCallModState::CALLPROC("CSipCallModState::CALLPROC", 1);
CSipCallModState_RECVUPDATE CSipCallModState::RECVUPDATE("CSipCallModState::RECVUPDATE", 2);
CSipCallModState_SUCCESS CSipCallModState::SUCCESS("CSipCallModState::SUCCESS", 3);
CSipCallModState_ACTIVE CSipCallModState::ACTIVE("CSipCallModState::ACTIVE", 4);
CSipCallModState_RELEASE CSipCallModState::RELEASE("CSipCallModState::RELEASE", 5);
CSipCallModState_CLOSED CSipCallModState::CLOSED("CSipCallModState::CLOSED", 6);


void CSipCallModuleState::onInfo(CSipCallModuleContext& context, TUniNetMsg* msg)
{
	 Default(context);
	 return;
}

void CSipCallModuleState::onUpdate(CSipCallModuleContext& context, TUniNetMsg* msg)
{
	 Default(context);
	 return;
}

void CSipCallModuleState::onAck(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    Default(context);
    return;
}

void CSipCallModuleState::onBye(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    Default(context);
    return;
}

void CSipCallModuleState::onCancel(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    Default(context);
    return;
}

void CSipCallModuleState::onInvite(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    Default(context);
    return;
}

void CSipCallModuleState::onResponse(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    Default(context);
    return;
}

void CSipCallModuleState::onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark)
{
    Default(context);
    return;
}

void CSipCallModuleState::Default(CSipCallModuleContext& context)
{
//    throw (
//        TransitionUndefinedException(
//            context.getState().getName(),
//            context.getTransition()));

    return;
}

void CSipCallModState_Default::onInvite(CSipCallModuleContext& context, TUniNetMsg* msg)
{


    return;
}

void CSipCallModState_Default::onUpdate(CSipCallModuleContext& context, TUniNetMsg* msg){
	return;
}

void CSipCallModState_Default::onResponse(CSipCallModuleContext& context, TUniNetMsg* msg)
{


    return;
}

void CSipCallModState_Default::onAck(CSipCallModuleContext& context, TUniNetMsg* msg)
{


    return;
}

void CSipCallModState_Default::onCancel(CSipCallModuleContext& context, TUniNetMsg* msg)
{


    return;
}

void CSipCallModState_Default::onBye(CSipCallModuleContext& context, TUniNetMsg* msg)
{


    return;
}

void CSipCallModState_Default::onInfo(CSipCallModuleContext& context, TUniNetMsg* msg)
{


    return;
}

void CSipCallModState_Default::onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark)
{
    CSipCallModule& ctxt(context.getOwner());

    CSipCallModuleState& endState = context.getState();

    context.clearState();
    try
    {
        ctxt.endTask();
        context.setState(endState);
    }
    catch (...)
    {
        context.setState(endState);
        throw;
    }

    return;
}

void CSipCallModState_IDLE::onInvite(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());

    (context.getState()).Exit(context);
    context.clearState();
    try
    {
        ctxt.setTimer(SIPCALL_200OK_TIMEOUT);
        ctxt.sendToDispatcher(msg);
        context.setState(CSipCallModState::CALLPROC);
    }
    catch (...)
    {
        context.setState(CSipCallModState::CALLPROC);
        throw;
    }
    (context.getState()).Entry(context);

    return;
}

void CSipCallModState_CALLPROC::onCancel(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());

    (context.getState()).Exit(context);
    context.clearState();
    try
    {
        ctxt.stopTimer();
        ctxt.sendToDispatcher(msg);
        ctxt.setTimer(SIPCALL_ACK_TIMEOUT);
        context.setState(CSipCallModState::RELEASE);
    }
    catch (...)
    {
        context.setState(CSipCallModState::RELEASE);
        throw;
    }
    (context.getState()).Entry(context);

    return;
}

void CSipCallModState_CALLPROC::onUpdate(CSipCallModuleContext& context, TUniNetMsg* msg){
	CSipCallModule& ctxt(context.getOwner());

	(context.getState()).Exit(context);
	context.clearState();
	try
	{
		ctxt.stopTimer();
		ctxt.sendToDispatcher(msg);
		ctxt.setTimer(SIPCALL_200OK_TIMEOUT);
		context.setState(CSipCallModState::RECVUPDATE);
	}
	catch (...)
	{
		context.setState(CSipCallModState::RECVUPDATE);
		throw;
	}
	(context.getState()).Entry(context);

	return;

}

void CSipCallModState_CALLPROC::onResponse(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());

    if (true == ctxt.isResp1xx(msg))
    {
//    	 ctxt.stopTimer();
  //  	 ctxt.sendToDispatcher(msg);
    }
    else if (true == ctxt.isResp3xx_6xx(msg))
    {
        (context.getState()).Exit(context);
        context.clearState();
        try
        {
            ctxt.stopTimer();
            ctxt.sendToDispatcher(msg);
			if(!ctxt.isSipCaller())
			{
				ctxt.sendBackACK(msg);
				context.setState(CSipCallModState::CLOSED);
			}
			else
			{
            	ctxt.setTimer(SIPCALL_ACK_TIMEOUT);
            	context.setState(CSipCallModState::RELEASE);
			}
        }
        catch (...)
        {
			context.setState(CSipCallModState::CLOSED);
            throw;
        }
        (context.getState()).Entry(context);
    }
    else if (true == ctxt.isResp2xx(msg))
    {
        (context.getState()).Exit(context);
        context.clearState();
        try
        {
            ctxt.stopTimer();
            ctxt.sendToDispatcher(msg);
            ctxt.setTimer(SIPCALL_ACK_TIMEOUT);
            context.setState(CSipCallModState::SUCCESS);
        }
        catch (...)
        {
            context.setState(CSipCallModState::SUCCESS);
            throw;
        }
        (context.getState()).Entry(context);
    }
    else{
    	context.setState(CSipCallModState::CLOSED);
    	(context.getState()).Entry(context);
    }

    return;
}

void CSipCallModState_CALLPROC::onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark)
{
    CSipCallModule& ctxt(context.getOwner());

    (context.getState()).Exit(context);
    context.clearState();
    try
    {
        ctxt.handleTimeoutAtCallProcState();
        ctxt.setTimer(SIPCALL_ACK_TIMEOUT);
        context.setState(CSipCallModState::RELEASE);
    }
    catch (...)
    {
        context.setState(CSipCallModState::RELEASE);
        throw;
    }
    (context.getState()).Entry(context);

    return;
}

void CSipCallModState_RECVUPDATE::onCancel(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());

    (context.getState()).Exit(context);
    context.clearState();
    try
    {
        ctxt.stopTimer();
        ctxt.sendToDispatcher(msg);
        ctxt.setTimer(SIPCALL_200OK_TIMEOUT);
        context.setState(CSipCallModState::RELEASE);
    }
    catch (...)
    {
        context.setState(CSipCallModState::RELEASE);
        throw;
    }
    (context.getState()).Entry(context);

    return;
}

void CSipCallModState_RECVUPDATE::onResponse(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());


	TSipResp * sipResp = (TSipResp *) (msg->msgBody);
	printf("mg update answer %d\n", sipResp->statusCode);
	if(sipResp->body.content.length() == 0)
	{
		printf("mg update answer %d without sdp\n", sipResp->statusCode);
	}
	(context.getState()).Exit(context);
	context.clearState();
	try
	{
		ctxt.stopTimer();
		ctxt.sendToDispatcher(msg);
		ctxt.setTimer(SIPCALL_200OK_TIMEOUT);
		context.setState(CSipCallModState::CALLPROC);
	}
	catch (...)
	{
		context.setState(CSipCallModState::CALLPROC);
		throw;
	}
	(context.getState()).Entry(context);

    return;
}

void CSipCallModState_RECVUPDATE::onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark)
{
    CSipCallModule& ctxt(context.getOwner());

    (context.getState()).Exit(context);
    context.clearState();
    try
    {
        ctxt.handleTimeoutAtCallProcState();
        ctxt.setTimer(SIPCALL_200OK_TIMEOUT);
        context.setState(CSipCallModState::CALLPROC);
    }
    catch (...)
    {
        context.setState(CSipCallModState::CALLPROC);
        throw;
    }
    (context.getState()).Entry(context);

    return;
}



void CSipCallModState_SUCCESS::onAck(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());

    (context.getState()).Exit(context);
    context.clearState();
    try
    {
        ctxt.stopTimer();
        ctxt.sendToDispatcher(msg);
        context.setState(CSipCallModState::ACTIVE);
    }
    catch (...)
    {
        context.setState(CSipCallModState::ACTIVE);
        throw;
    }
    (context.getState()).Entry(context);

    return;
}

void CSipCallModState_SUCCESS::onInvite(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());

    CSipCallModuleState& endState = context.getState();

    context.clearState();
    try
    {
        ctxt.sendBack488NotAcceptableHere(msg);
        context.setState(endState);
    }
    catch (...)
    {
        context.setState(endState);
        throw;
    }

    return;
}



void CSipCallModState_SUCCESS::onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark)
{
	CSipCallModule& ctxt(context.getOwner());
    (context.getState()).Exit(context);
	ctxt.sendBackBYE();
    context.setState(CSipCallModState::CLOSED);
	(context.getState()).Entry(context);

    return;
}

void CSipCallModState_SUCCESS::onBye(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());

    if (true == ctxt.isByeFromRtc(msg))
    {
        (context.getState()).Exit(context);
        context.clearState();
        try
        {
            ctxt.sendToDispatcher(msg);
            ctxt.setTimer(SIPCALL_200OK_TIMEOUT);
            context.setState(CSipCallModState::RELEASE);
        }
        catch (...)
        {
            context.setState(CSipCallModState::RELEASE);
            throw;
        }
        (context.getState()).Entry(context);
    }
    else if (true == ctxt.isByeFromSip(msg))
    {
        (context.getState()).Exit(context);
        context.clearState();
        try
        {
            ctxt.sendToDispatcher(msg);
            ctxt.sendBack200OK(msg);
			context.setState(CSipCallModState::CLOSED);
        }
        catch (...)
        {
        	context.setState(CSipCallModState::CLOSED);
			throw;
        }
        (context.getState()).Entry(context);
    }
    else{
    	context.setState(CSipCallModState::CLOSED);
    	(context.getState()).Entry(context);
    }

    return;

}

void CSipCallModState_ACTIVE::onInvite(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());

    CSipCallModuleState& endState = context.getState();

    context.clearState();
    if(true == ctxt.isConfReINVITE(msg)){
    	try
    	{
    		printf("\n SIP-Side Receive Conf Re-Invite\n");
    		ctxt.setTimer(SIPCALL_200OK_TIMEOUT);
    		ctxt.sendToDispatcher(msg);
    		context.setState(CSipCallModState::CALLPROC);
    	}
    	catch (...)
    	{
    		context.setState(endState);
    		throw;
    	}
    }
    else{
    	try
		{
    		ctxt.sendBack488NotAcceptableHere(msg);
    		context.setState(endState);
		}
    	catch (...)
    	{
    		context.setState(endState);
    		throw;
    	}
    }

    return;
}

void CSipCallModState_ACTIVE::onInfo(CSipCallModuleContext& context, TUniNetMsg* msg)
{
	 CSipCallModule& ctxt(context.getOwner());

	 CSipCallModuleState& endState = context.getState();
	 context.clearState();

	 try
	 {
		 ctxt.sendBack200OK(msg);
		 ctxt.sendToDispatcher(msg);
		 context.setState(CSipCallModState::ACTIVE);
	  }
	 catch (...)
	 {
		 context.setState(endState);
		 throw;
	 }
}

void CSipCallModState_ACTIVE::onUpdate(CSipCallModuleContext& context, TUniNetMsg* msg){
	 CSipCallModule& ctxt(context.getOwner());

	 CSipCallModuleState& endState = context.getState();
	 context.clearState();
	 try
	 {
		 ctxt.sendBack200OK(msg);
		 context.setState(CSipCallModState::ACTIVE);
	  }
	 catch (...)
	 {
		 context.setState(endState);
		 throw;
	 }
}



void CSipCallModState_ACTIVE::onBye(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());

    if (true == ctxt.isByeFromRtc(msg))
    {
        (context.getState()).Exit(context);
        context.clearState();
        try
        {
            ctxt.sendToDispatcher(msg);
            ctxt.setTimer(SIPCALL_200OK_TIMEOUT);
            context.setState(CSipCallModState::RELEASE);
        }
        catch (...)
        {
            context.setState(CSipCallModState::RELEASE);
            throw;
        }
        (context.getState()).Entry(context);
    }
    else if (true == ctxt.isByeFromSip(msg))
    {
        (context.getState()).Exit(context);
        context.clearState();
        try
        {
            ctxt.sendToDispatcher(msg);
            ctxt.sendBack200OK(msg);
			context.setState(CSipCallModState::CLOSED);
        }
        catch (...)
        {
        	context.setState(CSipCallModState::CLOSED);
			throw;
        }
        (context.getState()).Entry(context);
    }   

    return;

}

void CSipCallModState_RELEASE::onAck(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());
	(context.getState()).Exit(context);
    context.clearState();
    try
    {
        ctxt.stopTimer();
		context.setState(CSipCallModState::CLOSED);
    }
    catch (...)
    {
        context.setState(CSipCallModState::CLOSED);
        throw;
    }
	(context.getState()).Entry(context);
    return;
}

void CSipCallModState_RELEASE::onResponse(CSipCallModuleContext& context, TUniNetMsg* msg)
{
    CSipCallModule& ctxt(context.getOwner());
	(context.getState()).Exit(context);

    context.clearState();
    try
    {
		ctxt.stopTimer();
        context.setState(CSipCallModState::CLOSED);
    }
    catch (...)
    {
		context.setState(CSipCallModState::CLOSED);
        throw;
    }
	(context.getState()).Entry(context);
    return;
}

void CSipCallModState_RELEASE::onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark)
{
	(context.getState()).Exit(context);

    context.clearState();
    try
    {
        context.setState(CSipCallModState::CLOSED);
    }
    catch (...)
    {
        context.setState(CSipCallModState::CLOSED);
        throw;
    }
	
	(context.getState()).Entry(context);
    return;
}

void CSipCallModState_CLOSED::Entry(CSipCallModuleContext& context)
{
	CSipCallModule& ctxt(context.getOwner());
	
	ctxt.endTask();

	return;
}

/*
 * Local variables:
 *  buffer-read-only: t
 * End:
 */
