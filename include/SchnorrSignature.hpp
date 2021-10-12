#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <chrono>


#include "libscapi/include/primitives/DlogOpenSSL.hpp"
#include "libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "libscapi/include/primitives/Hash.hpp"
#include "libscapi/include/primitives/HashOpenSSL.hpp"
#include "libscapi/include/infra/Common.hpp"



#include "./bvsma/include/functions.hpp"




class Signature
{
    public:
    biginteger part1;
    biginteger part2;
    

    void setSignature(const Signature &sig);
    
    Signature& operator= (const Signature &sig);
    string toString();
    Signature(const biginteger& p1, const biginteger& p2);
    Signature(string str);
    Signature(const Signature &sig);
    Signature();
    ~Signature();
};


class SchnorrSignature
{
private:
    biginteger signKey;     
    shared_ptr<GroupElement> verifKey;
    shared_ptr<OpenSSLDlogECFp> dlog;
public:    

    biginteger getSignKey();
    shared_ptr<GroupElement> getVerifKey(); 
    void setVerifKey(const shared_ptr<GroupElement> &verKey); 
    void setSignKey(const biginteger &signKey);
    void setKey(const shared_ptr<GroupElement> &verKey, const biginteger &signKey);
    void KeyGen();

    Signature Sign(const vector<byte> &msg);
    Signature SignVect(const vector<biginteger>& vectBigint, const vector<shared_ptr<GroupElement>>& vectElt);
    
    bool Verify(const Signature & sig, const vector<byte> &msg);
    bool VerifyVect(const Signature & sig, const vector<biginteger>&  vectBigint, const vector<shared_ptr<GroupElement>>& vectElt);

    SchnorrSignature(string fileName, string curveName);
    SchnorrSignature(const shared_ptr<OpenSSLDlogECFp> &dlog);
    ~SchnorrSignature();
};








class Component
{
    public:
    biginteger userId; 
    biginteger indexComp;  // r_i  
    shared_ptr<AsymmetricCiphertext> colEnc;    
    shared_ptr<AsymmetricCiphertext> scoreEnc;
    Signature colEncSig;    
    Signature scoreEncSig;  

    shared_ptr<AsymmetricCiphertext> getColEnc();
    shared_ptr<AsymmetricCiphertext> getScoreEnc();
    Signature getColEncSig();
    Signature getScoreEncSig();   
    
    
    void setColEnc(const shared_ptr<AsymmetricCiphertext>& colEnc);
    void setScoreEnc(const shared_ptr<AsymmetricCiphertext>& scoreEnc);
    void setColEncSig(const Signature& sig);
    void setScoreEncSig(const Signature& sig);

    
    void signColEnc(SchnorrSignature schnorr);
    void signScoreEnc(SchnorrSignature schnorr); 
    
    bool verifyColEncSig(SchnorrSignature schnorr);
    bool verifyScoreEncSig(SchnorrSignature schnorr);    

    Component(const biginteger& userId, const biginteger& indexComp, const shared_ptr<AsymmetricCiphertext>& colEnc, const shared_ptr<AsymmetricCiphertext>& scoreEnc, const Signature& sigCol, const Signature& sigScore);
    Component(const biginteger& userId, const biginteger& indexComp, const shared_ptr<AsymmetricCiphertext>& colEnc, const shared_ptr<AsymmetricCiphertext>& scoreEnc);
    Component(const Component& comp);
    Component();
    ~Component();
};




