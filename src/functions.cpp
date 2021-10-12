
#include "bvsma/include/functions.hpp"




using namespace std;
typedef unsigned char byte;






/* 
	Print ECFp point
*/


void printOpenSSLECFpPoint(string namePoint, shared_ptr<GroupElement> elt){
	auto gPoint = dynamic_cast<OpenSSLECFpPoint*>(elt.get());
	auto xG = gPoint->getX();
	auto yG = gPoint->getY();
	//cout << "Point " << namePoint << ": " << ((OpenSSLZpSafePrimeElement *)elt.get())->getElementValue() << endl;
	cout << "Point " << namePoint << ": " << endl;
	cout << "xG: "<< xG << endl;
	cout << "yG: "<< yG << endl;
}


/* print vector int map */

void printVectIntMap(string nameMsg, map<int, vector<int>> vectIntMap){
	cout << nameMsg << endl;
	for(auto t : vectIntMap){
		cout << "i = " << t.first << " | ";
		for(auto elt : t.second){
			cout << elt << " : ";
		}
		cout << endl;
	}
}


void printVectBigintMap(string nameMsg, map<int, vector<biginteger>> vectBigintMap){
	cout << nameMsg << endl;
	for(auto t : vectBigintMap){
		cout << "i = " << t.first << " | ";
		for(auto elt : t.second){
			cout << elt << " : ";
		}
		cout << endl;
	}
}


void printIntVect(string nameMsg, vector<int> vectInt){
    cout << nameMsg << endl;
	for(auto elt : vectInt){
			cout << elt << " : ";
    }
    cout << endl;
}


void printBigintVect(string nameMsg, vector<biginteger> vectBigint){
    cout << nameMsg << endl;
	for(auto elt : vectBigint){
			cout << elt << " : ";
    }
    cout << endl;
}


void printBoolVect(string nameMsg, vector<bool> vectBool){
    cout << nameMsg << endl;
	for(auto elt : vectBool){
			cout << elt << " : ";
    }
    cout << endl;
}


void printByteVect(vector<byte> byteVect, string msg){
	byte* arrayByte = new byte[byteVect.size()];
    copy_byte_vector_to_byte_array(byteVect, arrayByte, 0); 
	print_byte_array(arrayByte, byteVect.size(), msg); 
}











/* Generate Threshold set permuted and encrypted using pubKeyTH 
	this also can be used to generate ciphers for the form Enc(m), Enc(m+1), ....
*/

vector<shared_ptr<AsymmetricCiphertext>> generateThresholdEncSet(int seed, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> thresholdElgamal, biginteger T, size_t len){
	vector<shared_ptr<AsymmetricCiphertext>> thresholdEncSet;
	srand(seed + time(0));
	auto g = dlog->getGenerator();
    auto random = get_seeded_prg();
	auto q = dlog->getOrder();
    //auto qMinusOne = dlog->getOrder() - (biginteger)1;

    vector<biginteger> vectT;
    for(int i = 0 ; i<len ; i++){
        vectT.push_back(T+i);
    }

    shuffle(vectT.begin(), vectT.end(), default_random_engine(rand()));
    for(size_t i = 0; i<vectT.size() ; i++){
        auto r = getRandomInRange(1, q-1, random.get());
        auto gPowT = dlog->exponentiate(g.get(), vectT.at(i));
        thresholdEncSet.push_back(thresholdElgamal->encrypt(make_shared<GroupElementPlaintext>(gPowT), r));
    }
	return thresholdEncSet;
}


/* Generate cipher map from  bigint map all rows will be of the same size*/

map<int, vector<shared_ptr<AsymmetricCiphertext>>> generateCipherMapFixed(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, biginteger m, biginteger r, size_t rowLen, size_t colLen){
	map<int, vector<shared_ptr<AsymmetricCiphertext>>> cipherMap;
	for(size_t i = 0; i<rowLen ; i++){
		cipherMap[i] = generateVectElGamalCiphers(dlog, elgamal, m, r, colLen);
	}
	return cipherMap;
}




















/* For Template Generation */


/* Generate map permutation (for all rows) */

map<int, vector<int>> generateMapIntPermutation(int seed, size_t len, const vector<int>& vectBegin, const vector<int>& vectEnd){
	map<int, vector<int>> permutedMap;
	//printVectIntMap("permutedMap Before: ", permutedMap);
	for(size_t i = 0; i<len; i++){
		permutedMap[i] = vectIntPermutation( seed + i, vectBegin.at(i), vectEnd.at(i));
	}
	//printVectIntMap("permutedMap After: ", permutedMap);
	return permutedMap;
}

/* Template generation */

// by client

map<int, vector<Component>> generatePartialTemplate(biginteger userId, 
map<int, vector<int>> permutation, map<int, vector<shared_ptr<AsymmetricCiphertext>>> colEncMap, 
map<int, vector<shared_ptr<AsymmetricCiphertext>>> scoreEncMap){
	biginteger index;
	map<int, vector<Component>> temp;
	size_t colLen, sizeTemp = permutation.size();
	for(size_t i = 0; i<sizeTemp; i++){
		temp[i].clear();
		colLen = permutation[i].size();
		auto per = permutation[i];
		temp[i].resize(colLen);
		for(size_t j = 0; j<colLen; j++){
			index = userId + biginteger( (unsigned int) per.at(j) );
			temp[i].at(per.at(j)) = Component(userId, index, colEncMap[i].at(j), scoreEncMap[i].at(j));
		}
	}
	return temp;
}

// by Enrollement 


map<int, vector<Component>> generateTemplate(SchnorrSignature schnorr, map<int, vector<Component>> partialTemplate){
	map<int, vector<Component>> finalTemp; 
	
	size_t colLen, sizeTemp = partialTemplate.size();
	for(size_t i = 0; i<sizeTemp; i++){

		colLen = partialTemplate[i].size();
		finalTemp[i].resize(colLen);

		for(size_t j = 0; j<colLen; j++){
			auto comp = partialTemplate[i].at(j);
			comp.signColEnc(schnorr);
			comp.signScoreEnc(schnorr);
			finalTemp[i].at(j) = Component(comp);
		}
	}
	return finalTemp;
}























/* For Template Generation */







/* Generate a permutation of [begin , end] */

vector<biginteger> vectPermutation(int seed, biginteger begin, biginteger end){
	vector<biginteger> permuted;
	srand(seed + time(0));
	for(auto i = begin; i<end; i++){
		permuted.push_back(i);
	}
	shuffle ( permuted.begin(), permuted.end(), default_random_engine(rand()));
	return permuted;
}

/* Generate map permutation (for all rows) */

map<int, vector<biginteger>> generateMapPermutation(int seed, size_t len, vector<biginteger> vectBegin, vector<biginteger> vectEnd){
	map<int, vector<biginteger>> permutedMap;
	for(size_t i = 0; i<len; i++){
		permutedMap[i] = vectPermutation(seed + i, vectBegin.at(i), vectEnd.at(i));
	}
	return permutedMap;
}


/* Generate a permutation of [begin , end] */

vector<int> vectIntPermutation(int seed, int begin, int end){
	vector<int> permuted;
	srand(seed + time(0));
	for(auto i = begin; i<end; i++){
		permuted.push_back(i);
	}
	shuffle(permuted.begin(), permuted.end(), default_random_engine(rand()));	
	return permuted;
}



/* Generate a synthetic probe of size tempDimension=384 and values in [0 , colLen=10] */

vector<int> generateSyntheticProbe(int seed, int tempDim, int colLen){
	vector<int> probe;
	srand(seed + time(0));
	for(auto i = 0; i<tempDim; i++){
		// if(i % colLen == 0){
		// 	probe.push_back(1);
		// 	continue;
		// }
		probe.push_back(i % colLen);
	}
	shuffle(probe.begin(), probe.end(), default_random_engine(rand()));	
	return probe;
}




















/* 
	string vector to biginteger vector
*/

/* vector<biginteger> strVectToBigintVect(vector<string> strVect){
	vector<biginteger> result;
	for(str : strVect){
		result.push_back(biginteger(str));
	}
	return result;
} */


/* GpElt vector to strBigint vector  */



/* vector<string> gpEltVectToStrBigintVect(vector<shared_ptr<GroupElement>> vectGpElt){
	vector<string> result, strVect;
	result.resize(0);//(0), strVect;
	strVect.resize(0);
	string str;
	for(auto elt : vectGpElt){
		str = dynamic_cast<OpenSSLECFpPoint*>(elt.get())->generateSendableData()->toString();
		strVect = explode(str, ':');
		result.insert(result.end(), strVect.begin(), strVect.end());
		strVect.clear();
	}
	return result;
} */

vector<biginteger> gpEltVectToBigintVect(vector<shared_ptr<GroupElement>> vectGpElt){
	vector<biginteger> vectBigint;
	vectBigint.clear();
	for(size_t i = 0 ; i< vectGpElt.size() ; i++){
		auto gPoint = dynamic_cast<OpenSSLECFpPoint*>(vectGpElt.at(i).get());
		vectBigint.push_back(gPoint->getX());
		vectBigint.push_back(gPoint->getY());
	}
	return vectBigint;
}


vector<byte> gpEltVectToByteVect(vector<shared_ptr<GroupElement>> vectGpElt){
	vector<byte> result, vect;
	result.resize(0);
	vect.resize(0);
	for(size_t i = 0 ; i< vectGpElt.size() ; i++){
		auto bigintGpElt = ((OpenSSLZpSafePrimeElement *)vectGpElt.at(i).get())->getElementValue();
		auto arrayGpEltLen = bytesCount(bigintGpElt);
		byte* arrayElt = new byte[arrayGpEltLen];
		fastEncodeBigInteger(bigintGpElt, arrayElt, arrayGpEltLen);
		copy_byte_array_to_byte_vector(arrayElt, arrayGpEltLen, vect, 0);
		result.insert(result.end(), vect.begin(), vect.end());
		vect.resize(0);
		delete arrayElt;
	}
	return result;
}

vector<byte> vectBigintToByteVect(vector<biginteger> vectBigint){
	vector<byte> result, vect;
	result.resize(0);
	vect.resize(0);
	for(size_t i = 0 ; i< vectBigint.size() ; i++){
		auto eltLen = bytesCount(vectBigint.at(i));
		byte* arrayElt = new byte[eltLen];
		fastEncodeBigInteger(vectBigint.at(i), arrayElt, eltLen);
		copy_byte_array_to_byte_vector(arrayElt, eltLen, vect, 0);
		result.insert(result.end(), vect.begin(), vect.end());
		vect.resize(0);
		delete arrayElt;
	}
	return result;
}



vector<shared_ptr<GroupElement>> strToVectGpElt(shared_ptr<OpenSSLDlogECFp> dlog, string str){
	vector<shared_ptr<GroupElement>> vect;
	auto v = explode(str, ':');
	size_t len = v.size();
	vector<biginteger> biginVect;
	for (size_t i = 0; i < len; i+=2)
	{
		biginVect.push_back(biginteger(v.at(i)));
		biginVect.push_back(biginteger(v.at(i+1)));
		vect.push_back(dlog->generateElement(true, biginVect));
		biginVect.resize(0);
	}
	return vect;
}




/* vector<string> bigintVectToStrBigintVect(vector<biginteger> vectBigint){
	vector<string> result;
	unsigned int b;
	for(auto elt : vectBigint){
		b = (unsigned int) elt;
		result.push_back(to_string(b));
	}
	return result;
} */




/* 
	strBigint vector  to byteBigint vector 
*/

// vector<byte> strBiginVectToByteVector(vector<string> strVect){
// 	vector<byte> result;
// 	result.clear();
// 	/* size_t len;
// 	biginteger elt;
// 	byte* arrayElt; */
// 	for(auto str : strVect){
// 		auto elt = biginteger(str);
// 		auto len = bytesCount(elt);
//     	auto arrayElt = new byte[len];
//     	fastEncodeBigInteger(elt, arrayElt, len);
// 		copy_byte_array_to_byte_vector(arrayElt, len, result, 0);
// 	}
// 	return result;
// }












/* biginteger generateChallenge(vector<shared_ptr<GroupElement>> vectGpElt, biginteger order){
	shared_ptr<CryptographicHash> hashSHA256 = make_shared<OpenSSLSHA256>();
	
    auto vectBigint = gpEltVectToByteVect(vectGpElt);

    hashSHA256->update(vectBigint, 0, vectBigint.size()); 

    vector<byte> hashedChallenge;
	hashedChallenge.resize(0);
    hashSHA256->hashFinal(hashedChallenge, 0);

    byte* arrayByteChallenge = new byte[hashedChallenge.size()];
    copy_byte_vector_to_byte_array(hashedChallenge, arrayByteChallenge, 0);   

    auto challenge =  fastDecodeBigInteger(arrayByteChallenge, hashedChallenge.size());
    return challenge % order;
} */



biginteger generateChallenge(const vector<shared_ptr<GroupElement>>& vectGpElt, biginteger order){
	
	shared_ptr<CryptographicHash> hashSHA256 = make_shared<OpenSSLSHA256>();


	// auto bigintGPElt = toBigint(vectGpElt);
	// vector<biginteger> vect;
	// vect.resize(0);
	// vect.insert(vect.end(), bigintGPElt.begin(), bigintGPElt.end());	
	auto vect = toBigint(vectGpElt);


	vector<byte> vecttt;
	vecttt.resize(0);
	for(size_t i = 0; i<vect.size();  i++){
		auto eltLen = bytesCount(vect.at(i));
		byte* arrayElt = new byte[eltLen];
		fastEncodeBigInteger(vect.at(i), arrayElt, eltLen);	
		copy_byte_array_to_byte_vector(arrayElt, eltLen, vecttt, 0);
		hashSHA256->update(vecttt, 0, eltLen); 
		vecttt.resize(0);
		delete arrayElt;	
	}

    vector<byte> hashedChallenge;
    hashSHA256->hashFinal(hashedChallenge, 0);	

    byte* arrayByteChallenge = new byte[hashedChallenge.size()];
    copy_byte_vector_to_byte_array(hashedChallenge, arrayByteChallenge, 0); 
    auto challenge =  fastDecodeBigInteger(arrayByteChallenge, hashedChallenge.size());

    return challenge % order;
}



biginteger generateHashForSign(const vector<biginteger>& bigintVect, const vector<shared_ptr<GroupElement>>& vectGpElt, biginteger order){
	
	shared_ptr<CryptographicHash> hashSHA256 = make_shared<OpenSSLSHA256>();
	//cout << "===========================" << endl;

	auto bigintGPElt = gpEltVectToBigintVect(vectGpElt);

	auto vect = bigintVect;
	vect.insert(vect.end(), bigintGPElt.begin(), bigintGPElt.end());	

	auto vectBigint = vectBigintToByteVect(vect);
	//printByteVect(vectBigint, "vectBigint = ");
	hashSHA256->update(vectBigint, 1, vectBigint.size()-1); 

    vector<byte> hashedChallenge;
	hashedChallenge.clear();
    hashSHA256->hashFinal(hashedChallenge, 0);	

    byte* arrayByteChallenge = new byte[hashedChallenge.size()];
    copy_byte_vector_to_byte_array(hashedChallenge, arrayByteChallenge, 0); 
    auto challenge =  fastDecodeBigInteger(arrayByteChallenge, hashedChallenge.size());

	//printByteVect(hashedChallenge, "hashedChallenge = ");
	//cout << "===========================" << endl;
	delete arrayByteChallenge;

    return challenge % order;
}


// everything to bigint

vector<biginteger> toBigint(vector<shared_ptr<GroupElement>> vectGpElt){
	vector<biginteger> vectBigint;
	vectBigint.resize(0);
	for(size_t i = 0 ; i< vectGpElt.size() ; i++){
		auto gPoint = dynamic_cast<OpenSSLECFpPoint*>(vectGpElt.at(i).get());
		vectBigint.push_back(gPoint->getX());
		vectBigint.push_back(gPoint->getY());
	}
	return vectBigint;
}


// hash

biginteger hashToSignAndVerify(const vector<biginteger>& bigintVect, const vector<shared_ptr<GroupElement>>& vectGpElt, biginteger order){
	
	shared_ptr<CryptographicHash> hashSHA256 = make_shared<OpenSSLSHA256>();


	auto bigintGPElt = toBigint(vectGpElt);
	vector<biginteger> vect;
	vect.resize(0);
	vect.insert(vect.end(), bigintVect.begin(), bigintVect.end());
	vect.insert(vect.end(), bigintGPElt.begin(), bigintGPElt.end());	


	vector<byte> vecttt;
	vecttt.resize(0);
	for(size_t i = 0; i<vect.size();  i++){
		auto eltLen = bytesCount(vect.at(i));
		byte* arrayElt = new byte[eltLen];
		fastEncodeBigInteger(vect.at(i), arrayElt, eltLen);	
		copy_byte_array_to_byte_vector(arrayElt, eltLen, vecttt, 0);
		hashSHA256->update(vecttt, 0, eltLen); 
		vecttt.resize(0);
		delete arrayElt;	
	}

    vector<byte> hashedChallenge;
    hashSHA256->hashFinal(hashedChallenge, 0);	

    byte* arrayByteChallenge = new byte[hashedChallenge.size()];
    copy_byte_vector_to_byte_array(hashedChallenge, arrayByteChallenge, 0); 
    auto challenge =  fastDecodeBigInteger(arrayByteChallenge, hashedChallenge.size());
	delete arrayByteChallenge;
    return challenge % order;
}









/* generate Vector of Ciphers of the form Enc(m, r), Enc(m+1, r+1), Enc(m+2, r+2)... */

vector<shared_ptr<AsymmetricCiphertext>> generateVectElGamalCiphers(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, biginteger m, biginteger r, size_t len){
	vector<shared_ptr<AsymmetricCiphertext>> vectCipher;
	auto g = dlog->getGenerator();
	for (size_t i = 0; i < len; i++)
	{
		auto gPowM = dlog->exponentiate(g.get(), (biginteger)i + m);
		vectCipher.push_back(elgamal->encrypt(make_shared<GroupElementPlaintext>(gPowM), (biginteger)i + r));
	}
	return vectCipher;
}

vector<biginteger> generateVectBigintRand(biginteger q, size_t len){
	vector<biginteger> vectBigint;
	auto random = get_seeded_prg();
	for (size_t i = 0; i < len; i++)
	{         
		vectBigint.push_back(getRandomInRange(1, q - 1, random.get()));
	}	
	return vectBigint;
}

vector<biginteger> generateVectBigintFixed(biginteger mod, biginteger start, size_t len){
	vector<biginteger> vectBigint;
	for (size_t i = 0; i < len; i++)
	{         
		vectBigint.push_back((start + (biginteger)i) % mod);
	}	
	return vectBigint;
}

vector<shared_ptr<AsymmetricCiphertext>> generateVectElGamalCiphersFromVects(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<biginteger> vectM, vector<biginteger> vectR){
	vector<shared_ptr<AsymmetricCiphertext>> vectCipher;
	auto g = dlog->getGenerator();
	size_t len = vectM.size(); 
	for (size_t i = 0; i < len; i++)
	{
		auto gPowM = dlog->exponentiate(g.get(), vectM.at(i));
		vectCipher.push_back(elgamal->encrypt(make_shared<GroupElementPlaintext>(gPowM), vectR.at(i)));
	}
	return vectCipher;
}

map<int, vector<shared_ptr<AsymmetricCiphertext>>> encryptColIndices(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<int> maxNFQ){
    size_t rowLen = maxNFQ.size();
    biginteger zero(0);
    auto q = dlog->getOrder();
	map<int, vector<shared_ptr<AsymmetricCiphertext>>> cipherMap;
	for(size_t i = 0; i<rowLen ; i++){
        auto vectM = generateVectBigintFixed(q, zero, maxNFQ.at(i));
        auto vectR = generateVectBigintRand(q, maxNFQ.at(i));
		cipherMap[i] = generateVectElGamalCiphersFromVects(dlog, elgamal, vectM, vectR);
	}
	return cipherMap;
}

map<int, vector<shared_ptr<AsymmetricCiphertext>>> encryptRowsFromHELR(string dir, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, vector<int> vectQuantizedSample){
	auto q = dlog->getOrder();
    map<int, vector<shared_ptr<AsymmetricCiphertext>>> cipherMap;
    size_t numFeatures = vectQuantizedSample.size();
	for(size_t i = 0; i<numFeatures ; i++){
        auto llr = readRowfromHELRFile(dir, i, vectQuantizedSample.at(i));
        auto vectR = generateVectBigintRand(q, llr.size());
		cipherMap[i] = generateVectElGamalCiphersFromVects(dlog, elgamalTH, llr, vectR);
	}
	return cipherMap;
}




vector<shared_ptr<GroupElement>> getVectC1(vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
	vector<shared_ptr<GroupElement>> vectU;
	for(auto vectC : vectCipher){
		auto cipher = dynamic_cast<ElGamalOnGroupElementCiphertext*>(vectC.get());
        vectU.push_back(cipher->getC1());
	}
	return vectU;
}
vector<shared_ptr<GroupElement>> getVectC2(vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
	vector<shared_ptr<GroupElement>> vectV;
	for(auto vectC : vectCipher){
		auto cipher = dynamic_cast<ElGamalOnGroupElementCiphertext*>(vectC.get());
        vectV.push_back(cipher->getC2());
	}
	return vectV;
}


vector<shared_ptr<AsymmetricCiphertext>> inverseVectCipherElGamal(shared_ptr<OpenSSLDlogECFp> dlog, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
	vector<shared_ptr<AsymmetricCiphertext>> invVectCipher;
	for(auto cipher : vectCipher){
		invVectCipher.push_back(inverseCipherElGamal(dlog, cipher));
	}
	return invVectCipher;
}

shared_ptr<AsymmetricCiphertext> subtractTwoCipher(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher1, shared_ptr<AsymmetricCiphertext> cipher2){
	biginteger zero(0);
	auto invCipher2 = inverseCipherElGamal(dlog, cipher2);
	return elgamal->multiply(cipher1.get(), invCipher2.get(), zero);
}

vector<shared_ptr<AsymmetricCiphertext>> subtractTwoCipherVect(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher1, vector<shared_ptr<AsymmetricCiphertext>> vectCipher2){
	vector<shared_ptr<AsymmetricCiphertext>> subtractedCipherVect;
	shared_ptr<AsymmetricCiphertext> cipher1, cipher2;
	BOOST_FOREACH(boost::tie(cipher1, cipher2), boost::combine(vectCipher1, vectCipher2)){        
		subtractedCipherVect.push_back(subtractTwoCipher(dlog, elgamal, cipher1, cipher2));
	}
	return subtractedCipherVect;
}








/* Verify gpElt1 ==? gpElt2 */

bool areEqual(shared_ptr<GroupElement> elt1, shared_ptr<GroupElement> elt2){
	return ((((OpenSSLZpSafePrimeElement *)elt1.get())->getElementValue()) == (((OpenSSLZpSafePrimeElement *)elt2.get())->getElementValue()));
        
}



/* ElGamal cipher inverse:
*		cipher = (u , v)
*		cipherInv = (u^(-1), v^(-1))
*
*/



shared_ptr<AsymmetricCiphertext> inverseCipherElGamal(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<AsymmetricCiphertext> cipher) {
	auto u = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC1();
	auto v = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC2();
	auto invU = dlog->getInverse(u.get());
	auto invV = dlog->getInverse(v.get());
	return make_shared<ElGamalOnGroupElementCiphertext>(invU, invV);
}


/* ElGamal cipher blinded:
*		cipher = (u , v)
*		blindedCipher = (u^(r), v^(r))
*
*/

shared_ptr<AsymmetricCiphertext> blindCipherElGamal(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<AsymmetricCiphertext> cipher, biginteger r) {
	auto u = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC1();
	auto v = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC2();
	auto blindedU = dlog->exponentiate(u.get(),r);
	auto blindedV = dlog->exponentiate(v.get(),r);
	return make_shared<ElGamalOnGroupElementCiphertext>(blindedU, blindedV);
}

vector<shared_ptr<AsymmetricCiphertext>> blindVectCipherElGamal(shared_ptr<OpenSSLDlogECFp> dlog, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<biginteger> rBlindVect){
	vector<shared_ptr<AsymmetricCiphertext>> blindedVect;
	size_t len = vectCipher.size();
	for(size_t i = 0; i < len; i++){
		blindedVect.push_back(blindCipherElGamal(dlog, vectCipher.at(i), rBlindVect.at(i)));
	}
	return blindedVect;
}


vector<shared_ptr<GroupElement>> partiallyDecryptVectCiphers(shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
	vector<shared_ptr<GroupElement>> partialDecVect;
	for(auto cipher : vectCipher){
		auto partCipher = elgamal->decrypt(cipher.get());
 		auto partialCipher = dynamic_cast<GroupElementPlaintext*>(partCipher.get())->getElement();
		partialDecVect.push_back(partialCipher);
	}
	return partialDecVect;
}
















/* Verify  
* 			colEncSig Signatures:  vector<Component> 
* 			scoreEncSig Signatures:  vector<Component> 
* 
*/

bool verifyColEncSignatures(SchnorrSignature schnorr, vector<Component> vectComp){
	bool result = true;
	for(auto comp : vectComp){
		result = result && comp.verifyColEncSig(schnorr);
	}
	return result;
}

bool verifyScoreEncSignatures(SchnorrSignature schnorr, vector<Component> vectComp){
	bool result = true;
	for(auto comp : vectComp){
		result = result && comp.verifyScoreEncSig(schnorr);
	}
	return result;
}

vector<shared_ptr<AsymmetricCiphertext>> extractColEncFromTemp(vector<Component> vectComp){
	vector<shared_ptr<AsymmetricCiphertext>> colEncVect;
	colEncVect.clear();
	for(size_t i = 0 ; i<vectComp.size() ; i++){
		colEncVect.push_back(vectComp.at(i).colEnc);
	}
	return colEncVect;
}

vector<shared_ptr<AsymmetricCiphertext>> extractScoreEncFromTemp(vector<Component> vectComp){
	vector<shared_ptr<AsymmetricCiphertext>> scoreEncVect;
	scoreEncVect.clear();
	for(size_t i = 0 ; i<vectComp.size() ; i++){
		scoreEncVect.push_back(vectComp.at(i).scoreEnc);
	}
	return scoreEncVect;
}



vector<Component> pickSpecificComponents(vector<int> indexCompVect, map<int, vector<Component>> userTemplate){
	vector<Component> compFromTemp;
	compFromTemp.clear();
	size_t tempDim = userTemplate.size();
	for(size_t i = 0 ; i<tempDim ; i++){
		compFromTemp.push_back(userTemplate[i].at(indexCompVect.at(i)));		
	}
	return compFromTemp;
}


vector<shared_ptr<AsymmetricCiphertext>> pickSpecificCiphers(vector<int> indexCompVect, map<int, vector<shared_ptr<AsymmetricCiphertext>>> userTemplate){
	vector<shared_ptr<AsymmetricCiphertext>> cipherFromTemp;
	cipherFromTemp.clear();
	size_t tempDim = userTemplate.size();
	for(size_t i = 0 ; i<tempDim ; i++){
		cipherFromTemp.push_back(userTemplate[i].at(indexCompVect.at(i)));		
	}
	return cipherFromTemp;
}










vector<shared_ptr<AsymmetricCiphertext>> multEvenCipherVect(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher){
    vector<shared_ptr<AsymmetricCiphertext>> vect;
	biginteger zero(0);
    vect.clear();
    size_t len = vectCipher.size();
    len = len/2;              
    for(size_t i = 0; i < len; i++){
        auto multElt = elgamalTH->multiply(vectCipher.at(i).get(),vectCipher.at(len+i).get(), zero);
        vect.push_back(multElt);
    }
    return vect;
}

vector<shared_ptr<AsymmetricCiphertext>> multOddCipherVect(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher){
    vector<shared_ptr<AsymmetricCiphertext>> vect, vCipher;
	biginteger zero(0);
    vCipher = vectCipher;
    vect.clear();
    size_t len = vCipher.size();
    vect.push_back(vCipher.at(len-1));
    vCipher.pop_back();
    len = (len - 1) / 2;  
    if(len == 0){
        return vect;
    }            
    for(size_t i = 0; i < len; i++){
        auto multElt = elgamalTH->multiply(vCipher.at(i).get(),vCipher.at(len+i).get(), zero);
        vect.push_back(multElt);
    }
    return vect;
}


shared_ptr<AsymmetricCiphertext> multiplyCiphersOfVect(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher){
    vector<shared_ptr<AsymmetricCiphertext>> finalScore = vectCipher;
    vector<shared_ptr<AsymmetricCiphertext>> vect; 
    size_t len = finalScore.size();
    while(len > 1){        
        if((len % 2) == 1){
            vect.resize(0);
            vect = multOddCipherVect(elgamalTH, finalScore);
            finalScore.resize(0);
            finalScore.insert(finalScore.end(), vect.begin(), vect.end()); 
        } else if((len % 2) == 0){
            vect.resize(0);
            vect = multEvenCipherVect(elgamalTH, finalScore);
            finalScore.resize(0);
            finalScore.insert(finalScore.end(), vect.begin(), vect.end());             
        }  
        len = finalScore.size();     
    }
    return finalScore.at(0);
}

vector<shared_ptr<AsymmetricCiphertext>> subtractOneCipherFromCipherVect(shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, shared_ptr<AsymmetricCiphertext> cipher){
	vector<shared_ptr<AsymmetricCiphertext>> subtractedCipherVect;
    shared_ptr<AsymmetricCiphertext> ciph;
	BOOST_FOREACH(boost::tie(ciph) , boost::combine(vectCipher)){        
		subtractedCipherVect.push_back(subtractTwoCipher(dlog, elgamal, ciph, cipher));
	}
	return subtractedCipherVect;
}

bool finalDecryptionANDMatch(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, vector<shared_ptr<AsymmetricCiphertext>> vectCipherBlinded, vector<shared_ptr<GroupElement>> vectPartialDec){
    auto vectU = getVectC1(vectCipherBlinded);
    size_t len = vectCipherBlinded.size();
    for(size_t i = 0; i<len ; i++){
        auto cipherF = ElGamalOnGroupElementCiphertext(vectU.at(i), vectPartialDec.at(i));
        shared_ptr<AsymmetricCiphertext> cipherFinal = make_shared<ElGamalOnGroupElementCiphertext>(cipherF);
        auto plainF = elgamalTH->decrypt(cipherFinal.get()); 
        auto gpElt = dynamic_cast<GroupElementPlaintext*>(plainF.get())->getElement();
        if(gpElt->isIdentity()){
            cout << "plainF = " << gpElt->generateSendableData()->toString() << endl;
            return true;
        }
    }
    return false;
}


bool finalDecryptionANDMatchSH(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, vector<shared_ptr<AsymmetricCiphertext>> vectPartialDec){
    size_t len = vectPartialDec.size();
    for(size_t i = 0; i<len ; i++){
        auto plainF = elgamalTH->decrypt(vectPartialDec.at(i).get()); 
        auto gpElt = dynamic_cast<GroupElementPlaintext*>(plainF.get())->getElement();
        if(gpElt->isIdentity()){
            cout << "plainF = " << gpElt->generateSendableData()->toString() << endl;
            return true;
        }
    }
    return false;
}




vector<shared_ptr<AsymmetricCiphertext>> elgamalPartialDecryption(shared_ptr<ElGamalOnGroupElementEnc> elgamalTH, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
	auto vectPartialDec = partiallyDecryptVectCiphers(elgamalTH, vectCipher);
	vector<shared_ptr<AsymmetricCiphertext>> vect;
	size_t len = vectCipher.size();
	auto vectU = getVectC1(vectCipher);
	for(size_t i = 0; i<len ; i++){
		auto cipherF = ElGamalOnGroupElementCiphertext(vectU.at(i), vectPartialDec.at(i));
        shared_ptr<AsymmetricCiphertext> cipherFinal = make_shared<ElGamalOnGroupElementCiphertext>(cipherF);
		vect.push_back(cipherFinal);
	}
	return vect;
}

















/* vector<Component> pickSpecificComponents( vector<biginteger> indexCompVect, map<int, vector<Component>> userTemplate){
	vector<Component> compFromTemp;
	size_t tempDim = userTemplate.size();
	for(size_t i = 0 ; i<tempDim ; i++){
		compFromTemp.push_back(userTemplate[i].at((int) indexCompVect[i]));
	}
	return compFromTemp;
} */

bool verifyVectCompSignatures(vector<Component> vectComp, SchnorrSignature schnorr){
	bool result = true; 
	for(auto comp : vectComp){
		result = result && comp.verifyColEncSig(schnorr);
		result = result && comp.verifyScoreEncSig(schnorr);
	}
	return result;
}


vector<bool> verifyVectCompSignaturesVectBool(vector<Component> vectComp, SchnorrSignature schnorr){
	vector<bool> result; 
	for(size_t i = 0; i<vectComp.size() ; i++){
		auto res = vectComp.at(i).verifyColEncSig(schnorr);
		result.push_back(res);
	}
	for(size_t i = 0; i<vectComp.size() ; i++){
		auto ress = vectComp.at(i).verifyScoreEncSig(schnorr);
		result.push_back(ress);
	}
	return result;
}




vector<int> getIndexCompFromPermutation(vector<int> vectInt, map<int,vector<int>> permutation){
	vector<int> indexComp; 
	size_t perDim = permutation.size();
	for(size_t i = 0 ; i<perDim ; i++){
		indexComp.push_back(permutation[i].at(vectInt.at(i)));
	}
	return indexComp;
}














/*  sender Functions    */



void sendIntVect(shared_ptr<CommParty> channel, vector<int> index){
	channel->writeWithSize(to_string(index.size()));
	for(auto ind : index){
		channel->writeWithSize(to_string(ind));
	}
}




void sendBigint(shared_ptr<CommParty> channel, biginteger bigInt) {
	size_t size = bytesCount(bigInt);
	byte msgByte[size];
	encodeBigInteger(bigInt, msgByte, size);
	channel->writeWithSize(msgByte, size);
}

void sendVectBigint(shared_ptr<CommParty> channel, vector<biginteger> vecBigInt) {
	channel->writeWithSize(to_string(vecBigInt.size()));
	for (biginteger elt : vecBigInt) {
		sendBigint(channel, elt);
	}
}

void sendGpElt(shared_ptr<CommParty> channel, shared_ptr<GroupElement> elt) {
	auto eltSendable = elt->generateSendableData();
    string strElt = eltSendable->toString();
    auto eltByte = strElt.c_str();
	channel->writeWithSize(eltByte);
}

void sendVectGpElt(shared_ptr<CommParty> channel, vector<shared_ptr<GroupElement>> vectGpElt) {
	channel->writeWithSize(to_string(vectGpElt.size()));
	for (shared_ptr<GroupElement> elt : vectGpElt) {
		sendGpElt(channel, elt);
	}
}

void sendElGamalPubKey(shared_ptr<CommParty> channel, shared_ptr<PublicKey> pubKey) {
  shared_ptr<KeySendableData> pubKeySendable = ((ElGamalPublicKey*) pubKey.get())->generateSendableData();
  string strPubKey = pubKeySendable->toString();
  channel->writeWithSize(strPubKey);
}

void sendElGamalCipher(shared_ptr<CommParty> channel, shared_ptr<AsymmetricCiphertext> cipher) {	
	shared_ptr<AsymmetricCiphertextSendableData> cipherSendable = cipher->generateSendableData();
	string strCipher = cipherSendable->toString();
	channel->writeWithSize(strCipher);
}

void sendVectElGamalCipher(shared_ptr<CommParty> channel, vector<shared_ptr<AsymmetricCiphertext>> vectCipher) {
	channel->writeWithSize(to_string(vectCipher.size()));
	for(shared_ptr<AsymmetricCiphertext> elt : vectCipher) {
		sendElGamalCipher(channel, elt);
	}
}

void sendSignature(shared_ptr<CommParty> channel, Signature sig){
	sendBigint(channel, sig.part1);
	sendBigint(channel, sig.part2);
}

void sendComponent(shared_ptr<CommParty> channel, Component comp){
	sendBigint(channel, comp.userId);
	sendBigint(channel, comp.indexComp);
	sendElGamalCipher(channel, comp.colEnc);
	sendElGamalCipher(channel, comp.scoreEnc);
	sendSignature(channel, comp.colEncSig);
	sendSignature(channel, comp.scoreEncSig);
}

void sendVectComponent(shared_ptr<CommParty> channel, vector<Component> vectComp){
	channel->writeWithSize(to_string(vectComp.size()));
	for(auto comp : vectComp) {
		sendComponent(channel, comp);
	}
}

void sendMapOfVectComponent(shared_ptr<CommParty> channel, map<int, vector<Component>> mapOfVectComp){
	channel->writeWithSize(to_string(mapOfVectComp.size()));
	for(auto vectComp : mapOfVectComp) {
		sendVectComponent(channel, vectComp.second);
	}
}


void sendMapElGamalCipher(shared_ptr<CommParty> channel, map<int, vector<shared_ptr<AsymmetricCiphertext>>> mapCipher){
	channel->writeWithSize(to_string(mapCipher.size()));
	for(auto vectCiph : mapCipher) {
		sendVectElGamalCipher(channel, vectCiph.second);
	}
}














/*  receiver Functions    */


vector<int> receiveIntVect(shared_ptr<CommParty> channel){
	vector<int> vect;
	int size = stoi(receiveStr(channel));
	for(int i = 0 ; i<size ; i++){
		vect.push_back(stoi(receiveStr(channel)));
	}
	return vect;
}


string receiveStr(shared_ptr<CommParty> channel) {
	vector<byte> msg;
	channel->readWithSizeIntoVector(msg);
	const byte * msgByte = &(msg[0]);
	return string(reinterpret_cast<char const*>(msgByte), msg.size());
}

biginteger receiveBigint(shared_ptr<CommParty> channel) {
	vector<byte> msg;
	channel->readWithSizeIntoVector(msg);
	const byte* msgByte = &(msg[0]);	
	return decodeBigInteger(msgByte, msg.size());
}

vector<biginteger> receiveVectBigint(shared_ptr<CommParty> channel) {
	vector<biginteger> vectBigInt;
	int size = stoi(receiveStr(channel));
	for (int i = 0; i < size; i++) {
		vectBigInt.push_back(receiveBigint(channel));
	}
	return vectBigInt;
}

shared_ptr<GroupElement> receiveGpElt(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog) {
	shared_ptr<GroupElementSendableData> eltSendable = make_shared<ECElementSendableData>(0,0);
	vector<byte> msg; 
	channel->readWithSizeIntoVector(msg);
	eltSendable->initFromByteVector(msg);
	return dlog->reconstructElement(true, eltSendable.get());
}

vector<shared_ptr<GroupElement>> receiveVectGpElt(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog) {
	vector<shared_ptr<GroupElement>> vectGpElt;
	int size = stoi(receiveStr(channel));
	for (int i = 0; i < size; i++) {
		vectGpElt.push_back(receiveGpElt(channel, dlog));
	}
	return vectGpElt;
}

shared_ptr<PublicKey> receiveElGamalPubKey(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal) {
	shared_ptr<KeySendableData> pubKeySendable = make_shared<ElGamalPublicKeySendableData>(dlog->getIdentity()->generateSendableData());
	vector<byte> msg;
	channel->readWithSizeIntoVector(msg);
	pubKeySendable->initFromByteVector(msg);
	return elgamal->reconstructPublicKey(pubKeySendable.get());
}

shared_ptr<AsymmetricCiphertext> receiveElGamalCipher(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal) {
	shared_ptr<AsymmetricCiphertextSendableData> cipherSendable = make_shared<ElGamalOnGrElSendableData>(dlog->getIdentity()->generateSendableData(), dlog->getIdentity()->generateSendableData());
	vector<byte> msg;
	channel->readWithSizeIntoVector(msg);
	cipherSendable->initFromByteVector(msg);
	return elgamal->reconstructCiphertext(cipherSendable.get());
}

vector<shared_ptr<AsymmetricCiphertext>> receiveVectElGamalCipher(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal) {
	vector<shared_ptr<AsymmetricCiphertext>> vectCipher;
	int size = stoi(receiveStr(channel));
	for(int i=0; i<size; i++) {
		vectCipher.push_back(receiveElGamalCipher(channel, dlog, elgamal));
	}
	return vectCipher;
}

Signature receiveSignature(shared_ptr<CommParty> channel){
	auto part1 = receiveBigint(channel);
	auto part2 = receiveBigint(channel);
	return Signature(part1, part2);
}

Component receiveComponent(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<ElGamalOnGroupElementEnc> elgamalTH){
	auto userId = receiveBigint(channel);
	auto indexComp = receiveBigint(channel);
	auto colEnc = receiveElGamalCipher(channel, dlog, elgamal); // single ElGamal
	auto scoreEnc = receiveElGamalCipher(channel, dlog, elgamalTH); // Threshold ElGamal
	auto colEncSig = receiveSignature(channel);
	auto scoreEncSig = receiveSignature(channel);
	return Component(userId, indexComp, colEnc, scoreEnc, colEncSig, scoreEncSig);
}

vector<Component> receiveVectComponent(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<ElGamalOnGroupElementEnc> elgamalTH){
	vector<Component> vectComp;
	int size = stoi(receiveStr(channel));
	for(int i=0; i<size; i++) {
		vectComp.push_back(receiveComponent(channel, dlog, elgamal, elgamalTH));
	}
	return vectComp;
}


map<int, vector<Component>> receiveMapOfVectComponent(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<ElGamalOnGroupElementEnc> elgamalTH){
	map<int, vector<Component>> mapOfVectComp;
	int size = stoi(receiveStr(channel));
	for(int i=0; i<size; i++) {
		mapOfVectComp[i] = receiveVectComponent(channel, dlog, elgamal, elgamalTH);
	}
	return mapOfVectComp;
}

map<int, vector<shared_ptr<AsymmetricCiphertext>>> receiveMapElGamalCipher(shared_ptr<CommParty> channel, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal){
	map<int, vector<shared_ptr<AsymmetricCiphertext>>> mapCipher;
	int size = stoi(receiveStr(channel));
	for(int i=0; i<size; i++) {
		mapCipher[i] = receiveVectElGamalCipher(channel, dlog, elgamal);
	}
	return mapCipher;
}

















