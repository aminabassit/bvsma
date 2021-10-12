#pragma once


#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <chrono>
#include <stdlib.h> 
#include <boost/thread/thread.hpp>
#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>


#include "bvsma/include/functions.hpp"


using namespace std;
typedef unsigned char byte;


void ProverUsage();

void VerifierUsage();



/******************************\
|**** Interactive ZKProofs ****|
\******************************/




/* Prover */

/* Simple */
int zkPoKBasicProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<GroupElement> h, biginteger w);
int zkPoKSinglePlainProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, biginteger m, biginteger r);


/* Multiple AND */
int zkPoKMultiANDPlainProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<biginteger> vectM, vector<biginteger> vectR);




/* Verifier */

/* Simple */
bool zkPoKBasicVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<GroupElement> h);
bool zkPoKSinglePlainVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher);


/* Multiple AND */
bool zkPoKMultiANDPlainVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);






/**********************************\
|**** Non-Interactive ZKProofs ****|
\**********************************/



/* Prover */

/* Simple */
int niZKDecZeroProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher, biginteger x);
int niZKBlindedProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher, biginteger rBlind);
int niZKPartialDecProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<PublicKey> provThreshPubKey, shared_ptr<AsymmetricCiphertext> cipher, biginteger provPrivKey);


/* Multiple AND */
int niZKMultiANDDecZeroProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, biginteger x);
int niZKMultiANDBlindedProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<biginteger> rBlindVect);
int niZKMultiANDPartialDecProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<PublicKey> provThreshPubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, biginteger provPrivKey);




/* Verifier */

/* Simple */
bool niZKDecZeroVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher);
bool niZKBlindedVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher, shared_ptr<AsymmetricCiphertext> blindedCipher);
bool niZKPartialDecVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<PublicKey> provThreshPubKey, shared_ptr<AsymmetricCiphertext> cipher, shared_ptr<GroupElement> partialCipher);


/* Multiple AND */
bool niZKMultiANDDecZeroVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
bool niZKMultiANDBlindedVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<shared_ptr<AsymmetricCiphertext>> vectBlindedCipher);
bool niZKMultiANDPartialDecVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<PublicKey> provThreshPubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<shared_ptr<GroupElement>> partialCipherVect);
