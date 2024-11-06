#pragma once
#include <string>

class Hash
{
public:
    Hash(const std::string &filename);

    std::string sha1() const;
    
private:
    std::string _filename;
};