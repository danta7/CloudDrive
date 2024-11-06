#include "CloudiskServer.h"


int main()
{
    int cnt = 1;
    CloudiskServer& server = CloudiskServer::getInstance(cnt);
    server.loadModules();
    server.start(1234);
    return 0;
}
