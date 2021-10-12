
#include "bvsma/include/SchnorrSignature.hpp"


using namespace std;


void Signature::setSignature(const Signature &sig){
    this->part1 = sig.part1;
    this->part2 = sig.part2;
}

string Signature::toString(){
    return part1.str()+':'+part2.str();
}

Signature& Signature::operator= (const Signature &sig){ 
    part1 = sig.part1;
    part2 = sig.part2;
    return *this;
}

Signature::Signature(const biginteger& part1, const biginteger& part2)
{
    this->part1 = part1;
    this->part2 = part2;
}

Signature::Signature(string str){
    auto v = explode(str, ':');
    this->part1 = biginteger(v.at(0));
    this->part2 = biginteger(v.at(1));
}

Signature::Signature(const Signature &sig)
{
    this->part1 = sig.part1;
    this->part2 = sig.part2;
}

Signature::Signature()
{
    this->part1 = 0;
    this->part2 = 0;
}

Signature::~Signature()
{
}




//==============================================================



biginteger SchnorrSignature::getSignKey(){
    return this->signKey;
}

shared_ptr<GroupElement> SchnorrSignature::getVerifKey(){
    return this->verifKey;
}

void SchnorrSignature::setVerifKey(const shared_ptr<GroupElement> &verifKey){
    this->verifKey = verifKey;
}

void SchnorrSignature::setSignKey(const biginteger &signKey){
    this->signKey = signKey;
}

void SchnorrSignature::setKey(const shared_ptr<GroupElement> &verKey, const biginteger &signKey){
    this->verifKey = verifKey;
    this->signKey = signKey;
}

void SchnorrSignature::KeyGen()
{
    auto q = this->dlog->getOrder();
    auto g = this->dlog->getGenerator();
    auto gen = get_seeded_prg();
    this->signKey = getRandomInRange(1, q - 1, gen.get());
	this->verifKey = this->dlog->exponentiate(g.get(), signKey);    
}



Signature SchnorrSignature::Sign(const vector<byte> &msg){
    shared_ptr<CryptographicHash> hashSHA256 = make_shared<OpenSSLSHA256>();
    auto q = this->dlog->getOrder();
    auto g = this->dlog->getGenerator();
    auto gen = get_seeded_prg();

    // I = g^k from GroupElement to byteVect
    biginteger k = getRandomInRange(1, q - 1, gen.get());
    auto I = dlog->exponentiate(g.get(), k);

    auto bigintI = ((OpenSSLZpSafePrimeElement *)I.get())->getElementValue();
    size_t I_len = bytesCount(bigintI);
    byte* arrayI = new byte[I_len];
    fastEncodeBigInteger(bigintI, arrayI, I_len);
    vector<byte> vectI;
    copy_byte_array_to_byte_vector(arrayI, I_len, vectI, 0);


    // SHA256( I || msg) from byteVect to Biginteger
    hashSHA256->update(vectI, 0, vectI.size());
	hashSHA256->update(msg, 0, msg.size());     
	vector<byte> msgHashed(1,0);
	hashSHA256->hashFinal(msgHashed, 0);
    byte* msgSchnorrHashedArray = new byte[msgHashed.size()];

    copy_byte_vector_to_byte_array (msgHashed, msgSchnorrHashedArray, 0);

    auto R =  fastDecodeBigInteger(msgSchnorrHashedArray, msgHashed.size());
    auto S = (R * this->signKey + k)%q;

    return Signature(R, S);
}

Signature SchnorrSignature::SignVect(const vector<biginteger>& vectBigint, const vector<shared_ptr<GroupElement>>& vectElt){  
    auto q = this->dlog->getOrder();
    auto g = this->dlog->getGenerator();
    auto random = get_seeded_prg();
    auto vect = vectElt;    
    // I = g^k from GroupElement to byteVect
    biginteger k = getRandomInRange(1, q - 1, random.get());
    auto I = this->dlog->exponentiate(g.get(), k);
    vect.push_back(I);

    auto R = generateHashForSign(vectBigint, vect, q);
    auto S = (R * this->signKey + k)%q;
    return Signature(R, S);
}





bool SchnorrSignature::Verify(const Signature & sig, const vector<byte> &msg){

    shared_ptr<CryptographicHash> hashSHA256 = make_shared<OpenSSLSHA256>();
    auto q = dlog->getOrder();
    auto g = dlog->getGenerator();
    

    // S = g^s
    auto S = dlog->exponentiate(g.get(), sig.part2);
    // R = y^(-r)
    auto invR = dlog->exponentiate(this->verifKey.get(), q-sig.part1);
    auto II = dlog->multiplyGroupElements(S.get(), invR.get());

    auto bigintII = ((OpenSSLZpSafePrimeElement *)II.get())->getElementValue();
    size_t II_len = bytesCount(bigintII);
    byte* arrayII = new byte[II_len];
    fastEncodeBigInteger(bigintII, arrayII, II_len);
    vector<byte> vectII;
    copy_byte_array_to_byte_vector(arrayII, II_len, vectII, 0);

    hashSHA256->update(vectII, 0, vectII.size());
	hashSHA256->update(msg, 0, msg.size());     
	vector<byte> msgHashed(1,0);
	hashSHA256->hashFinal(msgHashed, 0);

    byte* msgSchnorrHashedArray = new byte[msgHashed.size()];
    copy_byte_vector_to_byte_array (msgHashed, msgSchnorrHashedArray, 0);
    auto R =  fastDecodeBigInteger(msgSchnorrHashedArray, msgHashed.size());  

    cout << "R value is:          " << R << endl;
    cout << "sig.part1 value is:          " << sig.part1 << endl;
    return (sig.part1 == R);

}

bool SchnorrSignature::VerifyVect(const Signature & sig, const vector<biginteger>& vectBigint, const vector<shared_ptr<GroupElement>>& vectElt){
    auto q = dlog->getOrder();
    auto g = dlog->getGenerator();
    auto vect = vectElt;
    // S = g^s
    auto S = dlog->exponentiate(g.get(), sig.part2);
    // R = y^(-r)
    auto invR = dlog->exponentiate(this->verifKey.get(), q-sig.part1);
    auto I = dlog->multiplyGroupElements(S.get(), invR.get());   // g^k
    vect.push_back(I);   
    auto R = generateHashForSign(vectBigint, vect, q);
    return (sig.part1 == R);
}


SchnorrSignature::SchnorrSignature(string fileName, string curveName) 
{
    this->dlog = make_shared<OpenSSLDlogECFp>(fileName, curveName);

}

SchnorrSignature::SchnorrSignature(const shared_ptr<OpenSSLDlogECFp> &dlog) 
{
    this->dlog = dlog;

}


SchnorrSignature::~SchnorrSignature()
{
}




//===================================================================================










void Component::setColEnc(const shared_ptr<AsymmetricCiphertext>& colEnc){ this->colEnc = colEnc;}
void Component::setScoreEnc(const shared_ptr<AsymmetricCiphertext>& scoreEnc){ this->scoreEnc = scoreEnc;}
void Component::setColEncSig(const Signature& sig){ this->colEncSig = sig;}
void Component::setScoreEncSig(const Signature& sig){ this->scoreEncSig = sig;}


shared_ptr<AsymmetricCiphertext> Component::getColEnc(){ return this->colEnc;}
shared_ptr<AsymmetricCiphertext> Component::getScoreEnc(){ return this->scoreEnc;}
Signature Component::getColEncSig(){ return this->colEncSig;}
Signature Component::getScoreEncSig(){ return this->scoreEncSig;} 




void Component::signColEnc(SchnorrSignature schnorr){
    vector<shared_ptr<GroupElement>> colEncSigVectElt;  
    colEncSigVectElt.clear();
    vector<biginteger> indexVect;
    indexVect.clear();
    indexVect.push_back(userId);
    indexVect.push_back(indexComp);   
    auto cipherCol = dynamic_cast<ElGamalOnGroupElementCiphertext*>(colEnc.get());
    colEncSigVectElt.push_back(cipherCol->getC1());
    colEncSigVectElt.push_back(cipherCol->getC2());
    setColEncSig(schnorr.SignVect(indexVect, colEncSigVectElt));   
}


bool Component::verifyColEncSig(SchnorrSignature schnorr){
    vector<shared_ptr<GroupElement>> colEncSigVectElt;  
    colEncSigVectElt.clear();
    vector<biginteger> indexVect;
    indexVect.clear();
    indexVect.push_back(userId);
    indexVect.push_back(indexComp); 
    auto cipherCol = dynamic_cast<ElGamalOnGroupElementCiphertext*>(colEnc.get());
    colEncSigVectElt.push_back(cipherCol->getC1());
    colEncSigVectElt.push_back(cipherCol->getC2());    
    return schnorr.VerifyVect(colEncSig, indexVect, colEncSigVectElt);
}

void Component::signScoreEnc(SchnorrSignature schnorr){    
    vector<biginteger> indexVect;
    indexVect.clear();
    indexVect.push_back(userId);
    indexVect.push_back(indexComp);
    vector<shared_ptr<GroupElement>> scoreEncSigVectElt;
    scoreEncSigVectElt.clear(); 
    auto cipherCol = dynamic_cast<ElGamalOnGroupElementCiphertext*>(colEnc.get());
    scoreEncSigVectElt.push_back(cipherCol->getC1());
    scoreEncSigVectElt.push_back(cipherCol->getC2());   
    auto cipherScore = dynamic_cast<ElGamalOnGroupElementCiphertext*>(scoreEnc.get());
    scoreEncSigVectElt.push_back(cipherScore->getC1());
    scoreEncSigVectElt.push_back(cipherScore->getC2()); 
    setScoreEncSig(schnorr.SignVect(indexVect, scoreEncSigVectElt));
}



bool Component::verifyScoreEncSig(SchnorrSignature schnorr){
    vector<biginteger> indexVect;
    indexVect.clear();
    indexVect.push_back(userId);
    indexVect.push_back(indexComp);
    vector<shared_ptr<GroupElement>> scoreEncSigVectElt;
    scoreEncSigVectElt.clear(); 
    auto cipherCol = dynamic_cast<ElGamalOnGroupElementCiphertext*>(colEnc.get());
    scoreEncSigVectElt.push_back(cipherCol->getC1());
    scoreEncSigVectElt.push_back(cipherCol->getC2());   
    auto cipherScore = dynamic_cast<ElGamalOnGroupElementCiphertext*>(scoreEnc.get());
    scoreEncSigVectElt.push_back(cipherScore->getC1());
    scoreEncSigVectElt.push_back(cipherScore->getC2());   
    return schnorr.VerifyVect(scoreEncSig, indexVect, scoreEncSigVectElt);
}





Component::Component(const biginteger& userId, const biginteger& indexComp, const shared_ptr<AsymmetricCiphertext>& colEnc, const shared_ptr<AsymmetricCiphertext>& scoreEnc, const Signature& sigCol, const Signature& sigScore) : colEncSig(sigCol), scoreEncSig(sigScore){
    this->userId = userId;
    this->indexComp = indexComp;
    this->colEnc = colEnc;
    this->scoreEnc = scoreEnc;
}


Component::Component(const biginteger& userId, const biginteger& indexComp, const shared_ptr<AsymmetricCiphertext>& colEnc, const shared_ptr<AsymmetricCiphertext>& scoreEnc) : colEncSig(), scoreEncSig(){
    this->userId = userId;
    this->indexComp = indexComp;
    this->colEnc = colEnc;
    this->scoreEnc = scoreEnc;
}

Component::Component(const Component& comp)  : colEncSig(comp.colEncSig), scoreEncSig(comp.scoreEncSig) {
    this->userId = comp.userId;
    this->indexComp = comp.indexComp;
    this->colEnc = comp.colEnc;
    this->scoreEnc = comp.scoreEnc;
}

Component::Component() : colEncSig(), scoreEncSig(){}

Component::~Component(){}
