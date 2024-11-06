#include "CloudiskServer.h"
#include "Token.h"
#include"Hash.h"

#include <iostream>
#include <random>
#include <unistd.h>
#include <workflow/MySQLResult.h>
#include <workflow/MySQLMessage.h>
#include <vector>
#include <string>
#include <wfrest/json.hpp>
#include <sys/stat.h>


using std::cout;
using std::string;
using std::vector;
using namespace wfrest;

CloudiskServer &CloudiskServer::getInstance(int cnt)
{
    static CloudiskServer instance(cnt); // 确保只初始化一次
    return instance;
}

CloudiskServer::~CloudiskServer()
{
}

void CloudiskServer::start(unsigned short port)
{
    if (_httpServer.track().start(port) == 0)
    {
        _httpServer.list_routes();
        _waitGroup.wait();
        _httpServer.stop();
    }
    else
    {
        cout << "Cloudisk Server Start Failed\n";
    }
}

void CloudiskServer::loadModules()
{
    loadStaticResourceModule(); // 加载静态资源
    loadUserRegisterModule();   // 用户注册
    loadUserLoginModule();      // 用户登录
    loadUserInfoModule();
    loadFileQueryModule();
    loadFileUploadModule();
    loadFileDownloadModule();
}

void CloudiskServer::loadStaticResourceModule()
{
    // 加载所有的静态资源
    _httpServer.GET("/user/signup", [](const HttpReq *, HttpResp *resp)
                    { resp->File("static/view/signup.html"); });

    _httpServer.GET("/static/view/signin.html", [](const HttpReq *, HttpResp *resp)
                    { resp->File("static/view/signin.html"); });

    _httpServer.GET("/static/view/home.html", [](const HttpReq *, HttpResp *resp)
                    { resp->File("static/view/home.html"); });

    _httpServer.GET("/static/js/auth.js", [](const HttpReq *, HttpResp *resp)
                    { resp->File("static/js/auth.js"); });

    _httpServer.GET("/static/img/avatar.jpeg", [](const HttpReq *, HttpResp *resp)
                    { resp->File("static/img/avatar.jpeg"); });

    _httpServer.GET("/file/upload", [](const HttpReq *, HttpResp *resp)
                    { resp->File("static/view/index.html"); });
    _httpServer.Static("/file/upload_files", "static/view/upload_files");
}

// 用户注册
void CloudiskServer::loadUserRegisterModule()
{
    // 向"/usr/signup"发POST请求，三参数版本：需要序列执行新的任务->数据库
    _httpServer.POST("/user/signup", [this](const HttpReq *req, HttpResp *resp, SeriesWork *series)
                     {
        if(req->content_type() == APPLICATION_URLENCODED)
        {
            // 1.解析请求 获取用户名和密码
            auto formKV = req->form_kv();
            string userName = formKV["username"];
            string password = formKV["password"];
            if(userName.empty() || password.empty())
            {
                resp->String("not empty!");
                return;
            }
            cout << "userName : " << userName <<"\n";
            cout << "password : " << password << "\n";

            // 2.对密码进行加密
            string salt = generateSalt(8);  // 生成8自己的salt
            string encodePassword(crypt(password.c_str(),salt.c_str()));
            cout << "encodePassword : " << encodePassword <<"\n";

            // 将用户信息存储到数据库mysql中
            // 获取成员函数指针的方法！
            auto mysqlTask = WFTaskFactory::create_mysql_task(_mysqlurl,1,std::bind(&CloudiskServer::registerMysqlCB,this,std::placeholders::_1,resp));
            string sql("INSERT INTO cloudDrive.tbl_user(user_name,user_pwd,salt) VALUES('");
            sql += userName + "','" + encodePassword +"','" + salt +"')";
            cout << "sql : \n" << sql <<"\n";
            mysqlTask->get_req()->set_query(sql);
            series->push_back(mysqlTask);
        } });
}

void CloudiskServer::loadUserLoginModule()
{
    _httpServer.POST("/user/signin", [this](const HttpReq *req, HttpResp *resp, SeriesWork *series)
                     {
        // 1.解析请求
        auto formKV = req->form_kv();
        string userName = formKV["username"];
        string password = formKV["password"].c_str();
        cout << "userName: " << userName <<"\n";
        cout << "password : " << password << "\n";
        UserData* user_data = new UserData;
        user_data->password = password;
        user_data->userName = userName;
        series->set_context(user_data);

        // 2.对密码进行加密 根据用户名在数据库中取出盐值
        auto mysqlTask = WFTaskFactory::create_mysql_task(_mysqlurl,1,std::bind(&CloudiskServer::loginMysqlCB,this,std::placeholders::_1,resp));
        string sql = "SELECT salt, user_pwd FROM cloudDrive.tbl_user WHERE user_name = '";
        sql += userName +"' limit 1";
        cout << "sql :\n" << sql << "\n";
        mysqlTask->get_req()->set_query(sql);
        series->push_back(mysqlTask); });
}

// 信息加载
void CloudiskServer::loadUserInfoModule()
{
    _httpServer.GET("/user/info", [this](const HttpReq *req, HttpResp *resp, SeriesWork *series)
                    {
        // 1.解析请求
        string userName = req->query("username");
        string tokenStr = req->query("token");
        cout << "username: " << userName << "\n";
        cout << "tokenStr:" << tokenStr << "\n";

        validateToken(userName,tokenStr,series,[=](bool isValid){
            if(isValid)
            {
                UserData* user_data = new UserData;
                user_data->userName = userName;
                series->set_context(user_data);
                auto mysqlTask = WFTaskFactory::create_mysql_task(_mysqlurl,1,std::bind(&CloudiskServer::loadUserInfoMysqlCB,this,std::placeholders::_1,resp));

                string sql("select signup_at from cloudDrive.tbl_user where user_name = '");
                sql += userName + "'";
                mysqlTask->get_req()->set_query(sql);
                series->push_back(mysqlTask);
            }
            else
            {
                resp->String("Invalid token");
            }
        }); });
}

void CloudiskServer::loadFileQueryModule()
{
    _httpServer.POST("/file/query",[this](const HttpReq *req, HttpResp *resp, SeriesWork *series){
        // 解析请求：查询词
        string username = req->query("username");
        string tokenStr = req->query("token");
        cout << "username: " << username << "\n";
        cout << "tokenStr: " << tokenStr << "\n";
        UserData* user_data = new UserData;
        user_data->userName = username;
        series->set_context(user_data);
        validateToken(username,tokenStr,series,std::bind(&CloudiskServer::loadFileQueryWork,this,std::placeholders::_1,req,resp,series));
    });
}

void CloudiskServer::loadFileUploadModule()
{
    _httpServer.POST("/file/upload", [this](const HttpReq *req, HttpResp *resp, SeriesWork *series)
        {
            // 1.解析请求
            string username = req->query("username");
            string tokenStr = req->query("token");
            cout << "username:" << username << "\n";
            cout << "token:" << tokenStr << "\n";
            UserData* userdata = new UserData;
            userdata->userName = username;
            series->set_context(userdata);

            // 2.对token进行验证以及后续工作
            validateToken(username,tokenStr,series,std::bind(&CloudiskServer::loadFileUploadWork,this,std::placeholders::_1,req,resp,series));
         });
}

void CloudiskServer::loadFileDownloadModule()
{
    _httpServer.GET("/file/downloadurl",[](const HttpReq *req, HttpResp *resp)
    {    
        string filename = req->query("filename");
        //将下载业务从服务器中分离出去，之后只需要产生一个下载链接就可以了
        //去部署一个下载服务器->nginx
        string downloadURL = "http://192.168.5.129:4321/" + filename;
        resp->String(downloadURL);
    });
}

std::string CloudiskServer::generateSalt(size_t length)
{
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    std::random_device rd; // 生成随机种子
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, chars.size() - 1); // 生成在指定范围内均匀分布的整数
    string salt;
    for (size_t i = 0; i < length; i++)
    {
        salt += chars[distribution(generator)]; // 从字符集chars中随机选择字符并添加到salt中
    }
    return salt;
}

void CloudiskServer::registerMysqlCB(WFMySQLTask *mysqltask, HttpResp *resp)
{
    // 对任务的状态进行检测
    int state = mysqltask->get_state();
    int error = mysqltask->get_error();
    if (state != WFT_STATE_SUCCESS)
    {
        printf("%s\n", WFGlobal::get_error_string(state, error));
        return;
    }

    // 检测sql语句是否存在语法错误
    protocol::MySQLResponse *mysqlResp = mysqltask->get_resp();
    if (mysqlResp->get_packet_type() == MYSQL_PACKET_ERROR)
    {
        printf("ERROR %d:%s\n", mysqlResp->get_error_code(), mysqlResp->get_error_msg().c_str());
        resp->String("Signup Failed");
        return;
    }

    protocol::MySQLResultCursor cursor(mysqlResp);
    if (cursor.get_cursor_status() == MYSQL_STATUS_OK)
    {
        // 成功写入数据库
        printf("Query OK. %llu row affectted.\n", cursor.get_affected_rows());
        resp->String("SUCCESS");
    }
    else
    {
        resp->String("Signup Failed");
    }
}

void CloudiskServer::loginMysqlCB(WFMySQLTask *mysqltask, HttpResp *resp)
{
    // 对任务的状态进行检测
    int state = mysqltask->get_state();
    int error = mysqltask->get_error();
    if (state != WFT_STATE_SUCCESS)
    {
        printf("%s\n", WFGlobal::get_error_string(state, error));
        return;
    }
    // 检测SQL语句是否语法错误
    auto mysqlResp = mysqltask->get_resp();
    if (mysqlResp->get_packet_type() == MYSQL_PACKET_ERROR)
    {
        printf("ERROR %d:%s\n", mysqlResp->get_error_code(), mysqlResp->get_error_msg().c_str());
        resp->String("Singup Failed");
        return;
    }
    protocol::MySQLResultCursor cursor(mysqlResp);
    if (cursor.get_cursor_status() == MYSQL_STATUS_OK)
    {
        printf("Query OK. %llu row affected.\n", cursor.get_affected_rows());
        resp->String("Login Failed");
    }
    else if (cursor.get_cursor_status() == MYSQL_STATUS_GET_RESULT)
    {
        // 判断数据库中的密文和用户传进来的密文是否一样
        vector<vector<protocol::MySQLCell>> matrix;
        cursor.fetch_all(matrix);
        string salt = matrix[0][0].as_string();
        string pwd_m = matrix[0][1].as_string();
        auto user_data = static_cast<UserData *>(series_of(mysqltask)->get_context());
        string pwd = user_data->password;
        string username = user_data->userName;
        cout << "salt : " << salt << "\n";
        cout << "pwd_m : " << pwd_m << "\n";
        cout << "pwd : " << pwd << "\n";

        // 计算密文
        string encodedPassword(crypt(pwd.c_str(), salt.c_str()));
        if (encodedPassword == pwd_m)
        {
            // 1.登录成功的情况 生成Token信息
            Token token(username, salt);
            string tokenStr = token.genToken();
            // 2.构造一个Json对象发送给客户端
            using Json = nlohmann::json;
            Json msg;
            Json data;
            data["Token"] = tokenStr;
            data["Username"] = username;
            data["Location"] = "/static/view/home.html"; // 跳转到用户中心界面
            msg["data"] = data;
            resp->String(msg.dump()); // 序列化之后 发送给客户端

            // 3.将Token保存在redis数据库中
            int expire_seconds = 3600; // 1h
            auto redisTask = WFTaskFactory::create_redis_task(_redisurl, 1, nullptr);
            vector<string> redis_params = {username, std::to_string(expire_seconds), tokenStr};
            redisTask->get_req()->set_request("SETEX", redis_params);
            series_of(mysqltask)->push_back(redisTask);
        }
        else
        {
            resp->String("Login Failed");
        }
        delete user_data;
    }
}

void CloudiskServer::loadUserInfoMysqlCB(WFMySQLTask *mysqltask, HttpResp *resp)
{
    auto mysqlResp = mysqltask->get_resp();
    protocol::MySQLResultCursor cursor(mysqlResp);
    if (cursor.get_cursor_status() == MYSQL_STATUS_GET_RESULT)
    {
        // 读操作获取用户注册的时间
        vector<vector<protocol::MySQLCell>> matrix;
        cursor.fetch_all(matrix);
        string signupAt = matrix[0][0].as_string();
        UserData *user_data = static_cast<UserData *>(series_of(mysqltask)->get_context());
        string username = user_data->userName;
        using Json = nlohmann::json;
        Json msg;
        Json data;
        data["Username"] = username;
        data["SignupAt"] = signupAt;
        msg["data"] = data;
        resp->String(msg.dump());
        delete user_data;
    }
    else
    {
        // 没有读取到正确信息
        resp->String("error");
    }
}

void CloudiskServer::pwriteTaskCB(WFFileIOTask *IOtask,HttpResp* resp,int fd)
{
    if(IOtask->get_state() == WFT_STATE_SUCCESS)
    {
        UserData* user_data = static_cast<UserData*>(series_of(IOtask)->get_context());
        string filepath = user_data->filePath;
        string username = user_data->userName;
        string filehash = user_data->fileHsh;
        string filename = user_data->fileName;
        int countSize = user_data->contentsize;

        // 生成SHA1值
        cout << "filehash:" << filehash << "\n";

        // 将文件相关的信息写入数据库mysql中
        auto mysqlTask = WFTaskFactory::create_mysql_task(_mysqlurl,1,nullptr);
        string sql("INSERT INTO cloudDrive.tbl_user_file (user_name,file_sha1,file_size,file_name) VALUES('");
        sql += username + "','" + filehash + "','" + std::to_string(countSize) + "','" + filename +"')";
        cout << "\nsql:\n" << sql <<"\n";
        mysqlTask->get_req()->set_query(sql);
        series_of(IOtask)->push_back(mysqlTask);
        close(fd);
        delete user_data;
        resp->String("upload Sucess");
    }
    else
    {
        std::cerr << "File written successfully.\n";
        close(fd);
        resp->String("upload failed");
    }
}

void CloudiskServer::loadFileQueryMysqlCB(WFMySQLTask *mysqltask, HttpResp *resp)
{
    protocol::MySQLResponse* mysqlResp = mysqltask->get_resp();
    protocol::MySQLResultCursor cursor(mysqlResp);
    if(cursor.get_cursor_status() == MYSQL_STATUS_GET_RESULT)
    {
        // 读操作 获取用户的 
        vector<vector<protocol::MySQLCell>> matrix;
        cursor.fetch_all(matrix);
        using Json = nlohmann::json;
        Json msgArr;
        for(size_t i = 0; i<matrix.size(); ++i)
        {
            Json row;
            row["FileHash"] = matrix[i][0].as_string();
            row["FileName"] = matrix[i][1].as_string();
            row["FileSize"] = matrix[i][2].as_ulonglong();
            row["UploadAt"] = matrix[i][3].as_datetime();
            row["LastUpdated"] = matrix[i][4].as_datetime();
            msgArr.push_back(row);  // 在数组中添加一个元素
        }
        resp->String(msgArr.dump());
    }
    else
    {
        // 没有读到正确的信息
        resp->String("error");
    }
}

// 实现 validateToken 主函数
void CloudiskServer::validateToken(const string &username, const string &tokenStr, SeriesWork *series, std::function<void(bool)> callback)
{
    // 创建 Redis 任务检查 Redis 中是否有该 tokenStr
    auto redisTask = WFTaskFactory::create_redis_task(_redisurl, 1, [=](WFRedisTask *redisTask)
        {
        protocol::RedisResponse* resp = redisTask->get_resp();
        protocol::RedisValue value;
        resp->get_result(value);

        if (value.is_string() && value.string_value() == tokenStr) {
            // Redis 中 token 存在且有效
            callback(true);
        } else 
        {
            // Redis 中没有 token 或者 token 不匹配，需要从 MySQL 获取盐值
            checkTokenInMySQL(username, tokenStr, series, callback);
        } });

    redisTask->get_req()->set_request("GET", {username});
    series->push_back(redisTask);
}

// 从 MySQL 中查询盐值并生成 token 实现
void CloudiskServer::checkTokenInMySQL(const string &username, const string &tokenStr, SeriesWork *series, std::function<void(bool)> callback)
{
    auto mysqlTask = WFTaskFactory::create_mysql_task(_mysqlurl, 1, [=](WFMySQLTask *mysqlTask)
        {
        int state = mysqlTask->get_state();
        int error = mysqlTask->get_error();
        
        if (state != WFT_STATE_SUCCESS) {
            printf("%s\n", WFGlobal::get_error_string(state, error));
            callback(false);
            return;
        }

        protocol::MySQLResponse* mysqlResp = mysqlTask->get_resp();
        if (mysqlResp->get_packet_type() == MYSQL_PACKET_ERROR) {
            printf("ERROR %d: %s\n", mysqlResp->get_error_code(), mysqlResp->get_error_msg().c_str());
            callback(false);
            return;
        }

        protocol::MySQLResultCursor cursor(mysqlResp);
        if (cursor.get_cursor_status() == MYSQL_STATUS_GET_RESULT) {
            std::vector<std::vector<protocol::MySQLCell>> matrix;
            cursor.fetch_all(matrix);

            if (!matrix.empty()) {
                // 获取到盐值
                std::string salt = matrix[0][0].as_string();
                // 使用用户名和盐值生成新的 token
                Token newToken(username, salt);
                std::string generatedToken = newToken.genToken();

                if (generatedToken == tokenStr) {
                    // token 验证成功，将 token 存入 Redis
                    auto updateRedisTask = WFTaskFactory::create_redis_task(_redisurl, 1, nullptr);
                    updateRedisTask->get_req()->set_request("SETEX", {username, "3600", tokenStr});
                    series->push_back(updateRedisTask);

                    callback(true);
                    return;
                }
            }
        }

        // MySQL 查询失败或未找到对应的盐值，或 token 不匹配
        callback(false); });

    std::string sql = "SELECT salt FROM cloudDrive.tbl_user WHERE user_name = '" + username + "' LIMIT 1;";
    mysqlTask->get_req()->set_query(sql);
    series->push_back(mysqlTask);
}

void CloudiskServer::loadFileUploadWork(bool isValid, const HttpReq *req, HttpResp *resp, SeriesWork *series)
{
    // 解析请求 消息体
    if (req->content_type() == MULTIPART_FORM_DATA)
    {
        auto form = req->form();
        string filename = form["file"].first;
        vector<uint8_t> content(form["file"].second.begin(),form["file"].second.end());
        UserData* usrData = static_cast<UserData*>(series->get_context());
        string username = usrData->userName;
        
        // 将数据写入服务器本地
        mkdir("/home/danta/projects/CloudDrive/tmp",0755);

        string filepath = "/home/danta/projects/CloudDrive/tmp/" + filename;

        int fd = open(filepath.c_str(), O_CREAT|O_RDWR, 0664);
        if(fd < 0) 
        {
            perror("open");
            return;
        }
        Hash hash(filepath);
        string filehash = hash.sha1();

        usrData->userName = username;
        usrData->fileName = filename;
        usrData->filePath = filepath;
        usrData->fileHsh =  filehash;
        usrData->contentsize = content.size() ;
        series->set_context(usrData);

        auto fileWriteTask = WFTaskFactory::create_pwrite_task(fd,content.data(),content.size(),0,std::bind(&CloudiskServer::pwriteTaskCB,this,std::placeholders::_1,resp,fd));
        series->push_back(fileWriteTask);
  
    }
}

void CloudiskServer::loadFileQueryWork(bool isValid, const HttpReq *req, HttpResp *resp, SeriesWork *series)
{
    if(isValid)
    {
        string limitCnt = req->form_kv()["limit"];    // 列表限制
        auto mysqlTask = WFTaskFactory::create_mysql_task(_mysqlurl,1,std::bind(&CloudiskServer::loadFileQueryMysqlCB,this,std::placeholders::_1,resp));
        string sql("SELECT file_sha1, file_name, file_size, upload_at, last_update FROM cloudDrive.tbl_user_file WHERE user_name = '");
        UserData* user_data = static_cast<UserData*>(series->get_context());
        string username = user_data->userName;
        sql += username +"' limit " + limitCnt;
        cout << "\nsql:\n" << sql << "\n";
        mysqlTask->get_req()->set_query(sql);
        series->push_back(mysqlTask);
    
    }
    else
    {
        resp->String("Invalid token");
    }
}
