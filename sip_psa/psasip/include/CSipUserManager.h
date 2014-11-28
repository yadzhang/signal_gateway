#ifndef CUSERMAPMANAGER_H_
#define CUSERMAPMANAGER_H_

#include <vector>
#include <string>
using namespace std;
class CSipUserManager{
public:
	CSipUserManager();
	virtual ~CSipUserManager();
	static INT getSipUser(vector<string> &nameArr);		//get all sipname pool
	static INT setRegistered(string sipname, INT value);
	static INT setAllRegistered(INT value);
	static string getSipPassword(string sipname);
	static INT init();		//init database, set isRegistered = 0 and rtcname = ''
};


#endif
