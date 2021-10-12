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
#include<omp.h>

#include "libscapi/include/comm/Comm.hpp"
#include "libscapi/include/primitives/DlogOpenSSL.hpp"
#include "libscapi/include/interactive_mid_protocols/CommitmentSchemePedersenTrapdoor.hpp"
#include "libscapi/include/mid_layer/ElGamalEnc.hpp"
#include "libscapi/include/infra/Common.hpp"



#include "bvsma/include/functions.hpp"
#include "bvsma/include/ZKProofs.hpp"
#include "bvsma/include/SchnorrSignature.hpp"
#include "bvsma/include/fileFunctions.hpp"



class Component;
class Signature;
class SchnorrSignature;



vector<biginteger> generateVectBigintFixed_parallel(biginteger mod, biginteger start, size_t len);
vector<biginteger> generateVectBigintRand_parallel(biginteger q, size_t len);
vector<shared_ptr<AsymmetricCiphertext>> generateVectElGamalCiphersFromVects_parallel(string configFile, string curve , shared_ptr<PublicKey> pubKey, vector<biginteger> vectM, vector<biginteger> vectR);
map<int, vector<shared_ptr<AsymmetricCiphertext>>> encryptColIndices_parallel(string configFile, string curve , shared_ptr<PublicKey> pubKey, vector<int> maxNFQ);
map<int, vector<shared_ptr<AsymmetricCiphertext>>> encryptRowsFromLLR_parallel(string dir, string configFile, string curve , shared_ptr<PublicKey> pubKey, vector<int> vectQuantizedSample);
map<int, vector<Component>> generatePartialTemplate_parallel(biginteger userId, map<int, vector<int>> permutation, map<int, vector<shared_ptr<AsymmetricCiphertext>>> colEncMap, map<int, vector<shared_ptr<AsymmetricCiphertext>>> scoreEncMap);
vector<shared_ptr<AsymmetricCiphertext>> extractColEncFromTemp_parallel(vector<Component> vectComp);
vector<shared_ptr<AsymmetricCiphertext>> extractScoreEncFromTemp_parallel(vector<Component> vectComp);
map<int, vector<Component>> generateTemplate_parallel(string configFile, string curve, shared_ptr<GroupElement> verKey, biginteger signKey, map<int, vector<Component>> partialTemplate);
bool verifyVectCompSignatures_parallel(string configFile, string curve, shared_ptr<GroupElement> verKey, vector<Component> vectComp);
vector<shared_ptr<AsymmetricCiphertext>> subtractTwoCipherVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher1, vector<shared_ptr<AsymmetricCiphertext>> vectCipher2);
vector<shared_ptr<AsymmetricCiphertext>> multEvenCipherVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher);
vector<shared_ptr<AsymmetricCiphertext>> multOddCipherVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher);
shared_ptr<AsymmetricCiphertext> multiplyCiphersOfVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher);
vector<shared_ptr<AsymmetricCiphertext>> subtractOneCipherFromCipherVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, shared_ptr<AsymmetricCiphertext> cipher);
bool finalDecryptionANDMatch_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, shared_ptr<PrivateKey> privKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipherBlinded, vector<shared_ptr<GroupElement>> vectPartialDec);
vector<shared_ptr<GroupElement>> getVectC1_parallel(vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
vector<shared_ptr<GroupElement>> getVectC2_parallel(vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
vector<shared_ptr<AsymmetricCiphertext>> blindVectCipherElGamal_parallel(string configFile, string curve, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<biginteger> rBlindVect);
vector<shared_ptr<GroupElement>> partiallyDecryptVectCiphers_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, shared_ptr<PrivateKey> privKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
vector<shared_ptr<AsymmetricCiphertext>> elgamalPartialDecryption_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, shared_ptr<PrivateKey> privKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
vector<shared_ptr<AsymmetricCiphertext>> generateThresholdEncSet_parallel(int seed, string configFile, string curve, shared_ptr<PublicKey> pubKey, biginteger T, size_t len);













/* 
* ZKs parallel [Prover]
*/


int zkPoKMultiANDPlainProver_parallel(shared_ptr<CommParty> prover, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<biginteger> vectM, vector<biginteger> vectR);

int niZKMultiANDDecZeroProver_parallel(shared_ptr<CommParty> prover, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, biginteger x);
int niZKMultiANDBlindedProver_parallel(shared_ptr<CommParty> prover, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<biginteger> rBlindVect);
int niZKMultiANDPartialDecProver_parallel(shared_ptr<CommParty> prover, string configFile, string curve, shared_ptr<PublicKey> provThreshPubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, biginteger provPrivKey);



/* 
* ZKs parallel [Verifier]
*/
bool zkPoKMultiANDPlainVerifier_parallel(shared_ptr<CommParty> verifier, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);

bool niZKMultiANDBlindedVerifier_parallel(shared_ptr<CommParty> verifier, string configFile, string curve, shared_ptr<PublicKey> pubKey,vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<shared_ptr<AsymmetricCiphertext>> vectBlindedCipher);
bool niZKMultiANDPartialDecVerifier_parallel(shared_ptr<CommParty> verifier, string configFile, string curve, shared_ptr<PublicKey> provThreshPubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<shared_ptr<GroupElement>> partialCipherVect);
bool niZKMultiANDDecZeroVerifier_parallel(shared_ptr<CommParty> verifier, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);























