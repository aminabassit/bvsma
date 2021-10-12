#pragma once
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>
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


#include "bvsma/include/functions.hpp"
#include "bvsma/include/SchnorrSignature.hpp"


using namespace std;


class Component;
class Signature;
class SchnorrSignature;




biginteger readBigintFromfileInline(string filename, unsigned int num);
shared_ptr<GroupElement> readGPEltFromfileInline(string filename, shared_ptr<OpenSSLDlogECFp> dlog, unsigned int num);
shared_ptr<PublicKey> readPubKeyFromfileInLine(string filename, shared_ptr<OpenSSLDlogECFp> dlog, unsigned int num);
pair<unsigned long, vector<double>> readSampleWithIDInLine(string filename, int sample);
pair<unsigned long, vector<double>> readSampleWithIDInLineFPD(string filename, int sample);





biginteger readBigintFromfile(string filename, string partyID, string typeKey);
shared_ptr<GroupElement> readGPEltFromfile(string filename, shared_ptr<OpenSSLDlogECFp> dlog, string partyID, string typeKey);
vector<shared_ptr<AsymmetricCiphertext>> readVectCipherFromFile(string filename,  shared_ptr<OpenSSLDlogECFp> dlog);
shared_ptr<PublicKey> readPubKeyFromfile(string filename, shared_ptr<OpenSSLDlogECFp> dlog, string partyID, string typeKey);

vector<int> readSpecificPermutation(string filename, vector<int> rawProbe);
vector<Component> readSpecificCompTemplate(string filename, shared_ptr<OpenSSLDlogECFp> dlog, vector<int> indexComp);
map<int, vector<shared_ptr<AsymmetricCiphertext>>> readTemplateSH(string filename, shared_ptr<OpenSSLDlogECFp> dlog);



vector<int> quantizefeatures(string filename, vector<double> unQuantizedFeatures);
vector<int> quantizefeaturesFPD(string filename, vector<double> unQuantizedFeatures);
vector<biginteger> readRowfromHELRFile(string dir, int feature, int row);
vector<int> readMaxNFQ(string filename);
vector<double> readSample(string filename, int sample);
pair<unsigned long, vector<double>> readSampleWithID(string filename, int sample);






void writeBigintinFile(string filename, string partyID, string typeKey, biginteger bigint);
void writeGPELTinFile(string filename, string partyID, string typeKey, shared_ptr<GroupElement> gpElt);
void writeVectCipherinFile(string filename, vector<shared_ptr<AsymmetricCiphertext>> vectCipher);
void writePubKeyinFile(string filename, string partyID, string typeKey, shared_ptr<PublicKey> pubKey);
void writePermutation(string filename, map<int, vector<int>> permutation);
void writeTemplate(string dir, map<int, vector<Component>> userTemplate);
void writeTemplateSH(string dir, map<int, vector<shared_ptr<AsymmetricCiphertext>>> userTemplate);
void writeCSV(string filename, std::chrono::time_point<std::chrono::system_clock> start, bool endMeasure);
void writeCSVNew(std::ofstream& out_file, std::chrono::time_point<std::chrono::system_clock> start, bool endMeasure);
void writeResult(string filename, int resMatch);





