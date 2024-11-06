#include "Hash.h"
#include <fcntl.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <stdexcept>


Hash::Hash(const std::string &filename) :_filename(filename)
{
}

std::string Hash::sha1() const
{
    int fd = open(_filename.c_str(),O_RDONLY);
    if(fd < 0)
    {
        perror("open");
        return std::string();
    }
    unsigned char md[EVP_MAX_MD_SIZE];  // 存放哈希结果的数组
    unsigned int md_len;    // 实际哈希值长度
    char buff[1024] = {0};

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(ctx == nullptr)
    {
        close(fd);
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if(EVP_DigestInit_ex(ctx,EVP_sha1(),nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        close(fd);
        throw std::runtime_error("Failed to initialize SHA1");
    }

    while(true)
    {
        int ret = read(fd,buff,sizeof(buff));
        if(ret < 0)
        {
            perror("read");
            EVP_MD_CTX_free(ctx);
            close(fd);
            return std::string();
        }
        if(ret == 0)
        {
            break;
        }

        if (EVP_DigestUpdate(ctx,buff,ret)!= 1)
        {
            EVP_MD_CTX_free(ctx);
            close(fd);
            throw std::runtime_error("Failed to update SHA1 hash");
        }
    }
    if(EVP_DigestFinal_ex(ctx,md,&md_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        close(fd);
        throw std::runtime_error("Failed to finalize SHA1 hash");
    }

    EVP_MD_CTX_free(ctx);
    close(fd);
    // 将哈希值转为十六进制字符串
    std::string result;
    for(unsigned int i = 0 ;i<md_len;++i)
    {
        char fragment[3];
        sprintf(fragment,"%02x",md[i]);
        result += fragment;
    }
    return result;
}
