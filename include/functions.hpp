#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <boost/thread/thread.hpp>
#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>
#include <chrono>
#include <cstdlib>
#include <ctime>


#include "libscapi/include/comm/Comm.hpp"
#include "libscapi/include/primitives/DlogOpenSSL.hpp"
#include "libscapi/include/interactive_mid_protocols/CommitmentSchemePedersenTrapdoor.hpp"
#include "libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "libscapi/include/infra/Common.hpp"


#include "bvsma/include/SchnorrSignature.hpp"
#include "bvsma/include/fileFunctions.hpp"




class Component;
class Signature;
class SchnorrSignature;



/* Print Functions */
void printOpenSSLECFpPoint(string namePoint, shared_ptr<GroupElement> elt);
void printVectIntMap(string nameMsg, map<int, vector<int>> vectIntMap);
void printVectBigintMap(string nameMsg, map<int, vector<biginteger>> vectBigintMap);
void printIntVect(string msg, vector<int> vectInt);
void printBigintVect(string nameMsg, vector<biginteger> vectBigint);
void printBoolVect(string nameMsg, vector<bool> vectBool);
void printByteVect(vector<byte> byteVect, string msg);


/* Convertion Functions */
vector<biginteger> toBigint(vector<shared_ptr<GroupElement>> vectGpElt);
vector<byte> gpEltVectToByteVect(vector<shared_ptr<GroupElement>> vectGpElt);
vector<byte> vectBigintToByteVect(vector<biginteger> vectBigint);
vector<biginteger> gpEltVectToBigintVect(vector<shared_ptr<GroupElement>> vectGpElt);
vector<shared_ptr<GroupElement>> strToVectGpElt(shared_ptr<OpenSSLDlogECFp> dlog, string str);


/* Permutation Functions */
vector<biginteger> vectPermutation(int seed, biginteger begin, biginteger end);
vector<int> vectIntPermutation(int seed, int begin, int end);


/* Generate Functions */
vector<biginteger> generateVectBigintFixed(biginteger mod, biginteger start, size_t len);
vector<biginteger> generateVectBigintRand(biginteger q, size_t len);
vector<shared_ptr<AsymmetricCiphertext>> generateVectElGamalCiphers(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, biginteger m, biginteger r, size_t len);
vector<shared_ptr<AsymmetricCiphertext>> generateVectElGamalCiphersFromVects(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<biginteger> vectM, vector<biginteger> vectR);
vector<shared_ptr<AsymmetricCiphertext>> generateThresholdEncSet(int seed, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> thresholdElgamal, biginteger T, size_t len);
biginteger generateChallenge(const vector<shared_ptr<GroupElement>>& vectGpElt, biginteger order);
biginteger generateHashForSign(const vector<biginteger>& bigintVect, const vector<shared_ptr<GroupElement>>& vectGpElt, biginteger order);
vector<int> generateSyntheticProbe(int seed, int tempDim, int colLen);
map<int, vector<int>> generateMapIntPermutation(int seed, size_t len, const vector<int>& vectBegin, const vector<int>& vectEnd);
map<int, vector<shared_ptr<AsymmetricCiphertext>>> generateCipherMapFixed(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, biginteger m, biginteger r, size_t rowLen, size_t colLen);
map<int, vector<Component>> generatePartialTemplate(biginteger userId, map<int, vector<int>> permutation, map<int, vector<shared_ptr<AsymmetricCiphertext>>> colEncMap, map<int, vector<shared_ptr<AsymmetricCiphertext>>> scoreEncMap);
map<int, vector<Component>> generateTemplate( SchnorrSignature schnorr, map<int, vector<Component>> partialTemplate);
map<int, vector<biginteger>> generateMapPermutation(int seed, size_t len, vector<biginteger> vectBegin, vector<biginteger> vectEnd);


/* Get and Extract Functions */
vector<shared_ptr<GroupElement>> getVectC1(vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
vector<shared_ptr<GroupElement>> getVectC2(vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
vector<int> getIndexCompFromPermutation(vector<int> vectInt, map<int,vector<int>> permutation);
vector<shared_ptr<AsymmetricCiphertext>> extractColEncFromTemp(vector<Component> vectComp);
vector<shared_ptr<AsymmetricCiphertext>> extractScoreEncFromTemp(vector<Component> vectComp);
vector<Component> pickSpecificComponents(vector<int> indexCompVect, map<int, vector<Component>> userTemplate);
vector<shared_ptr<AsymmetricCiphertext>> pickSpecificCiphers(vector<int> indexCompVect, map<int, vector<shared_ptr<AsymmetricCiphertext>>> userTemplate);


/* Verify Functions */
bool verifyVectCompSignatures(vector<Component> vectComp, SchnorrSignature schnorr);
vector<bool> verifyVectCompSignaturesVectBool(vector<Component> vectComp, SchnorrSignature schnorr);
bool verifyColEncSignatures(SchnorrSignature schnorr, vector<Component> vectComp);
bool verifyScoreEncSignatures(SchnorrSignature schnorr, vector<Component> vectComp);
bool areEqual(shared_ptr<GroupElement> elt1, shared_ptr<GroupElement> elt2);
biginteger hashToSignAndVerify(const vector<biginteger>& bigintVect, const vector<shared_ptr<GroupElement>>& vectGpElt, biginteger order);


/* ElGamal and Threshold ElGamal Functions */
map<int, vector<shared_ptr<AsymmetricCiphertext>>> encryptColIndices(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<int> maxNFQ);
map<int, vector<shared_ptr<AsymmetricCiphertext>>> encryptRowsFromHELR(string dir, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, vector<int> vectQuantizedSample);
shared_ptr<AsymmetricCiphertext> inverseCipherElGamal(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<AsymmetricCiphertext> cipher);
vector<shared_ptr<GroupElement>> partiallyDecryptVectCiphers(shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
bool finalDecryptionANDMatch(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, vector<shared_ptr<AsymmetricCiphertext>> vectCipherBlinded, vector<shared_ptr<GroupElement>> vectPartialDec);
bool finalDecryptionANDMatchSH(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, vector<shared_ptr<AsymmetricCiphertext>> vectPartialDec);


/* Operation on Ciphers Functions */
vector<shared_ptr<AsymmetricCiphertext>> multEvenCipherVect(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher);
vector<shared_ptr<AsymmetricCiphertext>> multOddCipherVect(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher);
shared_ptr<AsymmetricCiphertext> multiplyCiphersOfVect(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher);
vector<shared_ptr<AsymmetricCiphertext>> subtractOneCipherFromCipherVect(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, shared_ptr<AsymmetricCiphertext> cipher);
vector<shared_ptr<AsymmetricCiphertext>> inverseVectCipherElGamal(shared_ptr<OpenSSLDlogECFp> dlog, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
shared_ptr<AsymmetricCiphertext> subtractTwoCipher(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher1, shared_ptr<AsymmetricCiphertext> cipher2);
vector<shared_ptr<AsymmetricCiphertext>> subtractTwoCipherVect(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher1, vector<shared_ptr<AsymmetricCiphertext>> vectCipher2);
shared_ptr<AsymmetricCiphertext> blindCipherElGamal(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<AsymmetricCiphertext> cipher, biginteger r);
vector<shared_ptr<AsymmetricCiphertext>> blindVectCipherElGamal(shared_ptr<OpenSSLDlogECFp> dlog, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<biginteger> rBlindVect);
vector<shared_ptr<AsymmetricCiphertext>> elgamalPartialDecryption(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);


/* Send Functions */
void sendIntVect(shared_ptr<CommParty> channel, vector<int> index);
void sendBigint(shared_ptr<CommParty> channel, biginteger bigInt);
void sendVectBigint(shared_ptr<CommParty> channel, vector<biginteger> vecBigInt);
void sendGpElt(shared_ptr<CommParty> channel, shared_ptr<GroupElement> elt);
void sendVectGpElt(shared_ptr<CommParty> channel, vector<shared_ptr<GroupElement>> vectGpElt);
void sendElGamalPubKey(shared_ptr<CommParty> channel, shared_ptr<PublicKey> pubKey);
void sendElGamalCipher(shared_ptr<CommParty> channel, shared_ptr<AsymmetricCiphertext> cipher);
void sendVectElGamalCipher(shared_ptr<CommParty> channel, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
void sendMapElGamalCipher(shared_ptr<CommParty> channel, map<int, vector<shared_ptr<AsymmetricCiphertext>>> mapCipher);
void sendSignature(shared_ptr<CommParty> channel, Signature sig);
void sendComponent(shared_ptr<CommParty> channel, Component comp);
void sendVectComponent(shared_ptr<CommParty> channel, vector<Component> vectComp);
void sendMapOfVectComponent(shared_ptr<CommParty> channel, map<int, vector<Component>> mapOfVectComp);


/* Receive Functions */
vector<int> receiveIntVect(shared_ptr<CommParty> channel);
string receiveStr(shared_ptr<CommParty> channel);
biginteger receiveBigint(shared_ptr<CommParty> channel);
vector<biginteger> receiveVectBigint(shared_ptr<CommParty> channel) ;
shared_ptr<GroupElement> receiveGpElt(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog);
vector<shared_ptr<GroupElement>> receiveVectGpElt(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog);
shared_ptr<PublicKey> receiveElGamalPubKey(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal);
shared_ptr<AsymmetricCiphertext> receiveElGamalCipher(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal);
vector<shared_ptr<AsymmetricCiphertext>> receiveVectElGamalCipher(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal);
map<int, vector<shared_ptr<AsymmetricCiphertext>>> receiveMapElGamalCipher(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal);
Signature receiveSignature(shared_ptr<CommParty> channel);
Component receiveComponent(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<ElGamalOnGroupElementEnc> elgamalTH);
vector<Component> receiveVectComponent(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<ElGamalOnGroupElementEnc> elgamalTH);
map<int, vector<Component>> receiveMapOfVectComponent(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<ElGamalOnGroupElementEnc> elgamalTH);


