#pragma once
#include <workflow/WFFacilities.h>
#include <wfrest/HttpServer.h>
#include <string>

using std::string;
using wfrest::HttpReq;
using wfrest::HttpResp;


struct UserData
{
    string userName;
    string password;
    string fileFd;
    string fileName;
    string filePath;
    string fileHsh;
    int contentsize;
};


class CloudiskServer
{
public:
    // 获取单例实例
    static CloudiskServer& getInstance(int cnt);

    // 禁用拷贝构造和赋值构造
    CloudiskServer(const CloudiskServer&) = delete;
    CloudiskServer& operator=(const CloudiskServer&) = delete;

    ~CloudiskServer();

    void start(unsigned short port);

    void loadModules();


private:
    CloudiskServer(int cnt) : _waitGroup(cnt),_mysqlurl("mysql://root:Dt1052323212.@localhost"),_redisurl("redis://127.0.0.1:6379")
    {
        
    }

private:
    // 模块化的思维方式编写代码
    void loadStaticResourceModule(); // 加载静态资源
    void loadUserRegisterModule();   // 用户注册
    void loadUserLoginModule();      // 用户登录
    void loadUserInfoModule();      //
    void loadFileQueryModule();     // 查询文件列表 
    void loadFileUploadModule();    // 文件上传
    void loadFileDownloadModule();
    
private:
    // 生成随机salt
    std::string generateSalt(size_t length);

    void registerMysqlCB(WFMySQLTask* mysqltask,HttpResp* resp);
    void loginMysqlCB(WFMySQLTask* mysqltask,HttpResp* resp);
    void loadUserInfoMysqlCB(WFMySQLTask* mysqltask,HttpResp* resp);
    void pwriteTaskCB(WFFileIOTask* task,HttpResp* resp,int fd);
    void loadFileQueryMysqlCB(WFMySQLTask* mysqltask,HttpResp* resp);

    // token 校验
    void validateToken(const string &username, const string &tokenStr, SeriesWork *series, std::function<void(bool)> callback);
    // 从 MySQL 中查询盐值并生成 token 实现
    void checkTokenInMySQL(const string &username, const string &tokenStr, SeriesWork *series,std::function<void(bool)> callback);
    // 上传文件任务
    void loadFileUploadWork(bool isValid,const HttpReq* req, HttpResp* resp, SeriesWork* series);
    // 查询文件列表任务
    void loadFileQueryWork(bool isValid,const HttpReq* req, HttpResp* resp, SeriesWork* series);


private:
    // 决定进程一启动就会阻塞在主线程中，而且会启动一个服务端实例
    WFFacilities::WaitGroup _waitGroup;
    wfrest::HttpServer _httpServer;
    std::string _mysqlurl;
    std::string _redisurl;
};