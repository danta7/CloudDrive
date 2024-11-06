#pragma once

#include <string>

using std::string;

class Token
{
public:
    Token(const string& unserName,const string& salt);

    string genToken() const;

    ~Token();
private:
    string _userName;
    string _salt;
};