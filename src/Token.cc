#include "Token.h"
#include <openssl/md5.h>
#include <sstream>
#include <openssl/evp.h>
#include <iomanip>

Token::Token(const string &unserName, const string &salt) : _userName(_userName), _salt(salt)
{
}

string Token::genToken() const
{
    // 根据用户名、盐值以及拼接时间生成token
    string tmp = _salt + _userName;
    unsigned char md[EVP_MAX_MD_SIZE]; // 生成的哈希值
    unsigned int md_len;               // 实际哈希值长度

    // 创建 MD5 上下文
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    // 初始化 MD5 算法
    if (EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, tmp.c_str(), tmp.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, md, &md_len) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to calculate MD5 hash");
    }

    // 释放 MD5 上下文
    EVP_MD_CTX_free(mdctx);

    // 将哈希值转换为十六进制字符
    std::ostringstream oss;
    for (unsigned int i = 0; i < md_len; ++i)
    {
        oss << std::hex <<std::setw(2) << std::setfill('0') << (int)md[i];
    }
    return oss.str();
}

Token::~Token()
{
}
