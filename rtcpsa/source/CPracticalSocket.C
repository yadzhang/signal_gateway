#include "CPracticalSocket.h"
#define MAXCONN 10


bool isJson(string& strMsg){
	Json::Reader reader;
	Json::Value jsonValue;
	if(reader.parse(strMsg, jsonValue) == false || jsonValue.type() != Json::objectValue)
		return false;
	return true;
}

void* ListenThread(void *pParam){
	CPracticalSocket& currSock = *(CPracticalSocket*)pParam;
	fd_set listenSet;
	int clientSocket;
	char buf[BUFFER_SIZE+1];
	struct sockaddr_in clientAddr;
	struct timeval timeout;
	int wcsfd = currSock.m_listenfds.wcsfd;
	int mediafd = currSock.m_listenfds.mediafd;
	int maxfd = mediafd > wcsfd?mediafd:wcsfd;
	while(!currSock.stop){

		//listen for mg and wcs socket created

		FD_ZERO(&listenSet);
		FD_SET(mediafd, &listenSet);
		FD_SET(wcsfd, &listenSet);

		//listen for receiving msg from mg or wcs
		for(set<int>::iterator it = currSock.m_wcsClifds.begin();
				it != currSock.m_wcsClifds.end(); ++it){
			FD_SET(*it, &listenSet);
			if(maxfd <= *it){
				maxfd = *it;
			}
		}

		vector<int> mgSockfds = currSock.m_mgClifds.getSockfds();

		for(vector<int>::iterator it = mgSockfds.begin();
				it != mgSockfds.end(); ++it){
			FD_SET(*it, &listenSet);
			if(maxfd <= *it){
				maxfd = *it;
			}
		}

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;


		int ret = select(maxfd + 1, &listenSet, NULL, NULL, &timeout);
		if(ret==-1){
			printf("ListenThread: select() failed!\n");
		}else if(ret==0){
			//printf("ListenThread: select() time out.\n");
		}else{
			//if seted, need not check other fd
			bool isSet = false;

			if(FD_ISSET(wcsfd, &listenSet)){
				isSet = true;
				cout<<"new wcs client coming"<<endl;
				socklen_t addrlen = sizeof(struct sockaddr_in);
				memset(&clientAddr, 0, sizeof(struct sockaddr_in));
				if((clientSocket = accept(wcsfd, (struct sockaddr*)&clientAddr, &addrlen))==-1){
					fprintf(stderr,"accept failed.\n");
				}

				currSock.m_wcsClifds.insert(clientSocket);
				
				char buff[100];
				int bytes = recv(clientSocket, buff, 100, 0);
				if(bytes <= 0){
					printf("Error, can not get server id when connect, so disconnect\n");
					close(clientSocket);
					continue;
				}
				buff[bytes]= '\0';


				printf("accept a connection from wcs server id %s,  %s:%u\n", buff,
						inet_ntoa(*(struct in_addr*)&(clientAddr.sin_addr.s_addr)),
						ntohs(clientAddr.sin_port));
				printf("new socket is: %u\n",clientSocket);

			}
			else if(!isSet && FD_ISSET(mediafd, &listenSet)){
				cout<<"new media client coming"<<endl;
				socklen_t addrlen = sizeof(struct sockaddr_in);
				memset(&clientAddr, 0, sizeof(struct sockaddr_in));
				if((clientSocket = accept(mediafd, (struct sockaddr*)&clientAddr, &addrlen))==-1){
					fprintf(stderr,"accept failed.\n");
				}

				// 读取消息长度
				u_int32_t packetlen = 0;
				if (recv(clientSocket, (char *) &packetlen, sizeof(u_int32_t), 0) <= 0){
					printf("can not get the size of domain when connect\n");
					close(clientSocket);
					continue;
				}
				packetlen = ntohl(packetlen);
				printf("CPracticalSocket: to recv %d.\n",packetlen);

				char buf[100];
				int bytes=recv(clientSocket, buf, packetlen, 0);
				if(bytes <= 0){
					printf("Error, can not get domain when connect, so disconnect\n");
					close(clientSocket);
					continue;
				}
				buf[bytes] = '\0';
				printf("get domain: %s\n", buf);


				currSock.m_mgClifds.Insert(clientSocket);


				printf("accept a connection from media_gateway %s:%u\n",
						inet_ntoa(*(struct in_addr*)&(clientAddr.sin_addr.s_addr)),
						ntohs(clientAddr.sin_port));
				printf("new socket is: %u\n",clientSocket);

			}
			else if(!isSet){
				for(vector<int>::iterator it = mgSockfds.begin();
						it != mgSockfds.end(); ++it){
					int fd = *it;
					if(FD_ISSET(fd, &listenSet)){
						isSet = true;
						//data from mg received
						// 读取消息长度
						u_int32_t packetlen = 0;
						if(recv(fd, (char *)&packetlen, sizeof(u_int32_t), 0) <= 0){
							printf("RecvThread:recv failed or socket closed by the media_gateway side.\n");

							close(fd);
							currSock.m_mgClifds.Delete(fd);
							continue;
						}

						packetlen = ntohl(packetlen);
						printf("CPracticalSocket: to recv %d.\n",packetlen);
						// 读取消息内容
						u_int32_t bufferSize = sizeof(buf) - 1;
						string strMsg;
						while(packetlen > 0){
							int toRead = packetlen > bufferSize ? bufferSize : packetlen;

							int bytes=recv(fd, buf, toRead, MSG_WAITALL);
							if(bytes==-1){
								printf("RecvThread: recv failed.\n");
								close(fd);
								currSock.m_mgClifds.Delete(fd);
								break;
							}else if(bytes==0){
								printf("RecvThread: socket closed by the other side.\n");
								close(fd);
								currSock.m_mgClifds.Delete(fd);
								break;
							}else{
							  buf[bytes] = '\0';
							  strMsg += buf;
							}
							packetlen -= bytes;
						}
						cout<<"recvMSg: ***"<<strMsg<<"***"<<"from media gateway socket: "<<fd<<endl;
						bool js = isJson(strMsg);
						if(js == true)
							currSock.msgBuffer.storeMsg(fd, strMsg);

						break;
					}

				}

				for(set<int>::iterator it = currSock.m_wcsClifds.begin();
					it != currSock.m_wcsClifds.end() && isSet == false; ++it){
					//test if data from wcs received
					if(FD_ISSET(*it, &listenSet)){
						string strMsg;
						int bytes = recv(*it, buf, BUFFER_SIZE, 0);
						if(bytes == -1){
							printf("RecvThread: recv failed.\n");
							close(*it);
							currSock.m_wcsClifds.erase(it);
							continue;
						}else if(bytes==0){
							printf("RecvThread: socket closed by the other side.\n");
							close(*it);
							currSock.m_wcsClifds.erase(it);
							continue;
						}

						buf[bytes] = '\0';
						strMsg += buf;
						printf("received msg: %s\n", strMsg.c_str());
						if(isJson(strMsg) == true)
						{
							CRtcProtocolParser rtcParser(strMsg);
							CRoapParser roapParser = rtcParser.getRoapParser();

							string offersessionId = roapParser.getOfferSessionId();
							cout<<"map offersessionId "<<offersessionId<<"to socket"<<*it<<endl;
							currSock.m_mapWcsSockets.insert(make_pair<string, int>(offersessionId, *it));

							cout<<"recvMSg: ***"<<strMsg<<"***"<<endl<<"from WCS socket: "<<*it<<endl;
							currSock.msgBuffer.storeMsg(*it, strMsg);
						}

						break;
					}
				}
			}
		}
	}
	return NULL;
}




CPracticalSocket::CPracticalSocket():m_tListenId(0), stop(false){
	// should get from config
	// m_listenPort = 9870;
	m_wcsClifds.clear();

}

CPracticalSocket::~CPracticalSocket(){
	cout<<"call desc"<<endl;
	stopThread();
	pthread_join(m_tListenId, NULL);

	for(set<int>::iterator it = m_wcsClifds.begin();
			  it != m_wcsClifds.end(); ++it){
		cout<<"close wcs socketfd: "<<*it<<endl;
		close(*it);
	}


	vector<int> mgSockfds = m_mgClifds.getSockfds();

	for(vector<int>::iterator it = mgSockfds.begin(); it!= mgSockfds.end(); ++it){
		cout<<"close mg socketfd:"<<*it<<endl;
		close(*it);
	}

	m_mgClifds.clear();
	m_wcsClifds.clear();
	m_mapWcsSockets.clear();
	close(m_listenfds.mediafd);
	close(m_listenfds.wcsfd);
}

bool CPracticalSocket::init(int mediaPort, int wcsPort){
	m_mediaPort = mediaPort;
	m_wcsPort = wcsPort;

//	m_mgClifd = -1;
	cout<<"listen on media: "<<m_mediaPort<<", wcs: "<<m_wcsPort<<endl;


	//prepare for listening media_gateway connect request
	int mediaSocket = 0;
	if((mediaSocket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) == -1){
		cout<<"create socket failed"<<endl;
		return false;
	}
	
	int opt = 1;
	setsockopt(mediaSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in serverAddr;
	bzero(&serverAddr,sizeof(struct sockaddr_in));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(m_mediaPort);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(mediaSocket,(struct sockaddr*)&serverAddr,sizeof(serverAddr))==-1){
		cout<<"bind socket to port "<<mediaPort<<" failed"<<endl;
		return false;
	}

	if(listen(mediaSocket, MAXCONN)==-1){
		cout<<"listen failed"<<endl;
		return false;
	}

	m_listenfds.mediafd = mediaSocket;


	int wcsSocket = 0;
	if((wcsSocket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) == -1){
		cout<<"create socket failed"<<endl;
		return false;
	}
	opt = 1;
	setsockopt(wcsSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in serverAddr2;
	bzero(&serverAddr2,sizeof(struct sockaddr_in));
	serverAddr2.sin_family = AF_INET;
	serverAddr2.sin_port = htons(m_wcsPort);
	serverAddr2.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(wcsSocket,(struct sockaddr*)&serverAddr2,sizeof(serverAddr2))==-1){
		cout<<"bind socket to port "<<wcsPort<<" failed"<<endl;
		return false;
	}

	if(listen(wcsSocket, MAXCONN)==-1){
		cout<<"listen failed"<<endl;
		return false;
	}

	m_listenfds.wcsfd = wcsSocket;

	// create listenThread
	if(pthread_create(&m_tListenId, NULL, ListenThread, this) != 0){
		cout<<"failed to create listen thread"<<endl;
		stop = true;
		return false;
	}
	
	cout<<"succuss init"<<endl;
	return true;
}

bool CPracticalSocket::recvMsg(int& sockfd, string& msg){
	return msgBuffer.getMsg(sockfd, msg);
}

bool CPracticalSocket::sendMsg(int clientSock, string msg, bool isSendToMG){
	cout<<"send msg "<<msg<<" to "<<clientSock<<endl;
	fd_set writeSet;
	FD_ZERO(&writeSet);
	FD_SET(clientSock, &writeSet);
	int ret = select(clientSock + 1, NULL, &writeSet, NULL, NULL);
    if(ret == -1){
    	printf("SendThread: select() failed!\n");
    }else if(ret==0){
      //printf("SendThread: select() time out.\n");
    }else{
        if(FD_ISSET(clientSock, &writeSet)){
        	if(isSendToMG == false){
        		//MSG need send to WCS
        		cout<<"able to send to WebRtc Server"<<endl;

        		int bytes = send(clientSock, msg.c_str(), msg.length(), 0);
        		if(bytes == -1){
					printf("SendThread: send() failed.\n");
					return false;
        		}else if(bytes != msg.length()){
					printf("SendThread: send message trunked.");
				}else{
					//do nothing
					cout<<"send to webrtc server succesfully"<<endl;

				}
        	}else{
				cout<<"able to send to MEDIA_GATEWAY"<<endl;
				Packet packet;
				strncpy(packet.buf, msg.c_str(), BUFFER_SIZE);
				int msgSize = strlen(packet.buf);
				packet.len = htonl(msgSize);
				int bytes = send(clientSock, (char *)&packet, msgSize + sizeof(packet.len), 0);

		//       	int messageLen = msg.size();
		//      	int bytes = send(clientSock, msg.c_str(), messageLen, 0);
				if(bytes == -1){
					printf("SendThread: send() failed.\n");
					return false;
				}else if(bytes != msgSize + sizeof(packet.len)){
					printf("SendThread: send message trunked.");
				}else{
				//do nothing
					cout<<"send to MEDIA_GATEWAY succesfully"<<endl;
				}
        	}
        }
    }
	return true;
}

void CPracticalSocket::insertNewMgMap(const string& offersessionId){
	if(m_mapMgSockets.find(offersessionId) == m_mapMgSockets.end()){
		if(!m_mgClifds.empty()){
			m_mapMgSockets.insert(make_pair<string, int>(offersessionId, m_mgClifds.GetHeadMGSocket()));
			return;
		}
		else{
			cout<<"ERROR: no media connected to sg!!!"<<endl;
			return;
		}
	}

}

int CPracticalSocket::deleteMgMap(const string & offersessionId){
	if(m_mapMgSockets.find(offersessionId) != m_mapMgSockets.end()){
		m_mapMgSockets.erase(offersessionId);
		cout<<"CPractialSocket::delete m_mapMgSocket item successfully:"<<offersessionId<<endl;
		return 0;
	}
	else{
		cout<<"CPractialSocket::delete m_mapMgSocket item failed:"<<offersessionId<<endl;
		return -1;
	}
}

int CPracticalSocket::getClientSocketByDomain(const string& offersessionId, const bool isSendToMg){
	if(isSendToMg){
		if(m_mapMgSockets.find(offersessionId) != m_mapMgSockets.end()){
			int sockfd = (m_mapMgSockets.find(offersessionId))->second;
			if(m_mgClifds.CheckSockfd(sockfd)){
				cout<<"m_mgClifds has socket, sockfd is"<<sockfd<<" \n";
				return sockfd;
			}
			else{
				cout<<"ERROR: media gateway "<<offersessionId<<" break down!!!"<<endl;
				return -1;
			}
		}
		else{
			cout<<"ERROR: no map item for "<<offersessionId<<endl;
			return -1;
		}

	}
	else{
		if(m_mapWcsSockets.find(offersessionId) != m_mapWcsSockets.end()){
			int sockfd = m_mapWcsSockets[offersessionId];
			if(m_wcsClifds.find(sockfd) != m_wcsClifds.end()){
				return sockfd;
			}
			else{
				m_mapWcsSockets.erase(offersessionId);
				if(!m_wcsClifds.empty()){
					return *(m_wcsClifds.begin());
				}
				else{
					cout<<"ERROR:no wcs connected to sg!!!"<<endl;
					return -1;
				}
			}
		}else{
			if(!m_wcsClifds.empty()){
				return *(m_wcsClifds.begin());
			}
			else{
				cout<<"ERROR:no wcs connected to sg!!!"<<endl;
				return -1;
			}
		}
	}
	return -1;
}

string CPracticalSocket::getDomainbySocket(int sockfd){
	for(map<string, int>::const_iterator it = m_mapWcsSockets.begin(); it != m_mapWcsSockets.end(); ++it){
		if(it->second == sockfd)
			return it->first;
	}
	return NULL;
}

bool CPracticalSocket::isFromMg(int sockfd){

	return m_mgClifds.CheckSockfd(sockfd);

}


