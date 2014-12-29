#ifndef _H_CSIPCALLMODULE_SM
#define _H_CSIPCALLMODULE_SM

/*
 * ex: set ro:
 * DO NOT EDIT.
 * generated by smc (http://smc.sourceforge.net/)
 * from file : CSipCallModule_sm.sm
 */


#define SMC_USES_IOSTREAMS

#include <statemap.h>

// Forward declarations.
class CSipCallModState;
class CSipCallModState_IDLE;
class CSipCallModState_CALLPROC;
class CSipCallModState_RECVUPDATE;
class CSipCallModState_SUCCESS;
class CSipCallModState_ACTIVE;

class CSipCallModState_RELEASE;

//State CLOSED added by zhangyadong on 2014-7-13
class CSipCallModState_CLOSED;
class CSipCallModState_Default;
class CSipCallModuleState;
class CSipCallModuleContext;
class CSipCallModule;

class CSipCallModuleState :
    public statemap::State
{
public:

    CSipCallModuleState(const char *name, int stateId)
    : statemap::State(name, stateId)
    {};

    virtual void Entry(CSipCallModuleContext&) {};
    virtual void Exit(CSipCallModuleContext&) {};

    virtual void onAck(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onBye(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onCancel(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onInvite(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onResponse(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onInfo(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onUpdate(CSipCallModuleContext& context, TUniNetMsg* msg);

    virtual void onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark);


protected:

    virtual void Default(CSipCallModuleContext& context);
};

class CSipCallModState
{
public:

    static CSipCallModState_IDLE IDLE;
    static CSipCallModState_CALLPROC CALLPROC;
    static CSipCallModState_RECVUPDATE RECVUPDATE;
    static CSipCallModState_SUCCESS SUCCESS;
    static CSipCallModState_ACTIVE ACTIVE;
    static CSipCallModState_RELEASE RELEASE;

	static CSipCallModState_CLOSED CLOSED;
}; 

class CSipCallModState_Default :
    public CSipCallModuleState
{
public:

    CSipCallModState_Default(const char *name, int stateId)
    : CSipCallModuleState(name, stateId)
    {};

    virtual void onInvite(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onUpdate(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onResponse(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onAck(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onCancel(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onBye(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onInfo(CSipCallModuleContext& context, TUniNetMsg* msg);
    virtual void onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark);
};

class CSipCallModState_IDLE :
    public CSipCallModState_Default
{
public:
    CSipCallModState_IDLE(const char *name, int stateId)
    : CSipCallModState_Default(name, stateId)
    {};

    void onInvite(CSipCallModuleContext& context, TUniNetMsg* msg);
};

class CSipCallModState_RECVUPDATE:
        public CSipCallModState_Default
{
public:
    CSipCallModState_RECVUPDATE(const char *name, int stateId)
	: CSipCallModState_Default(name, stateId)
	{};

	void onCancel(CSipCallModuleContext& context, TUniNetMsg* msg);
	void onResponse(CSipCallModuleContext& context, TUniNetMsg* msg);
	void onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark);
};


class CSipCallModState_CALLPROC :
    public CSipCallModState_Default
{
public:
    CSipCallModState_CALLPROC(const char *name, int stateId)
    : CSipCallModState_Default(name, stateId)
    {};

    void onCancel(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onUpdate(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onResponse(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark);
};

class CSipCallModState_SUCCESS :
    public CSipCallModState_Default
{
public:
    CSipCallModState_SUCCESS(const char *name, int stateId)
    : CSipCallModState_Default(name, stateId)
    {};

    void onAck(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onInvite(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark);

	void onBye(CSipCallModuleContext& context, TUniNetMsg* msg);
};

class CSipCallModState_ACTIVE :
    public CSipCallModState_Default
{
public:
    CSipCallModState_ACTIVE(const char *name, int stateId)
    : CSipCallModState_Default(name, stateId)
    {};

    void onBye(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onUpdate(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onInvite(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onInfo(CSipCallModuleContext& context, TUniNetMsg* msg);
};

class CSipCallModState_RELEASE :
    public CSipCallModState_Default
{
public:
    CSipCallModState_RELEASE(const char *name, int stateId)
    : CSipCallModState_Default(name, stateId)
    {};

    void onAck(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onResponse(CSipCallModuleContext& context, TUniNetMsg* msg);
    void onTimeOut(CSipCallModuleContext& context, TTimeMarkExt timerMark);
};

//added(whole class) by zhangyadong on 2014.7.13
class CSipCallModState_CLOSED:
	public CSipCallModState_Default
{
	public:
		CSipCallModState_CLOSED(const char *name, int stateId)
		: CSipCallModState_Default(name, stateId){}
		void Entry(CSipCallModuleContext&);
};
class CSipCallModuleContext :
    public statemap::FSMContext
{
public:

    CSipCallModuleContext(CSipCallModule& owner)
    : FSMContext(CSipCallModState::IDLE),
      _owner(owner)
    {};

    CSipCallModuleContext(CSipCallModule& owner, const statemap::State& state)
    : FSMContext(state),
      _owner(owner)
    {};

    virtual void enterStartState()
    {
        getState().Entry(*this);
        return;
    }

    CSipCallModule& getOwner() const
    {
        return (_owner);
    };

    CSipCallModuleState& getState() const
    {
        if (_state == NULL)
        {
            throw statemap::StateUndefinedException();
        }

        return (dynamic_cast<CSipCallModuleState&>(*_state));
    };

    void onAck(TUniNetMsg* msg)
    {
        (getState()).onAck(*this, msg);
    };

    void onBye(TUniNetMsg* msg)
    {
        (getState()).onBye(*this, msg);
    };

    void onCancel(TUniNetMsg* msg)
    {
        (getState()).onCancel(*this, msg);
    };

    void onInvite(TUniNetMsg* msg)
    {
        (getState()).onInvite(*this, msg);
    };

    void onInfo(TUniNetMsg * msg)
    {
    	(getState()).onInfo(*this, msg);
    };


    void onResponse(TUniNetMsg* msg)
    {
        (getState()).onResponse(*this, msg);
    };

    void onTimeOut(TTimeMarkExt timerMark)
    {
        (getState()).onTimeOut(*this, timerMark);
    };

private:

    CSipCallModule& _owner;
};


/*
 * Local variables:
 *  buffer-read-only: t
 * End:
 */

#endif // _H_CSIPCALLMODULE_SM
