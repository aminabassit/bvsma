#include "bvsma/include/functionsParallel.hpp"



using namespace std;
typedef unsigned char byte;






vector<biginteger> generateVectBigintFixed_parallel(biginteger mod, biginteger start, size_t len){
	vector<biginteger> vectBigint;
    vectBigint.resize(len);
    #pragma omp parallel for schedule(static,1)
	for (size_t i = 0; i < len; i++)
	{         
		vectBigint.at(i) = (start + (biginteger)i) % mod;
	}	
	return vectBigint;
}

vector<biginteger> generateVectBigintRand_parallel(biginteger q, size_t len){
	vector<biginteger> vectBigint;
    vectBigint.resize(len);
	auto random = get_seeded_prg();
    auto qMinusOne = q - (biginteger)1;
    #pragma omp parallel for schedule(static,1)
	for (size_t i = 0; i < len; i++)
	{         
		vectBigint.at(i) =  getRandomInRange(1, qMinusOne, random.get());
	}	
	return vectBigint;
}

vector<shared_ptr<AsymmetricCiphertext>> generateVectElGamalCiphersFromVects_parallel(string configFile, string curve , shared_ptr<PublicKey> pubKey, vector<biginteger> vectM, vector<biginteger> vectR){
    
    size_t len = vectM.size(); 
	vector<shared_ptr<AsymmetricCiphertext>> vectCipher;
    vectCipher.resize(len);    
	
    #pragma omp parallel for schedule(static,1)
	for (size_t i = 0; i < len; i++)
	{
		auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);
        elgamal->setKey(pubKey);
	    auto g = dlog->getGenerator();
        auto gPowM = dlog->exponentiate(g.get(), vectM.at(i));
		vectCipher.at(i) = elgamal->encrypt(make_shared<GroupElementPlaintext>(gPowM), vectR.at(i));
	}

	return vectCipher;
}

map<int, vector<shared_ptr<AsymmetricCiphertext>>> encryptColIndices_parallel(string configFile, string curve , shared_ptr<PublicKey> pubKey, vector<int> maxNFQ){
    size_t rowLen = maxNFQ.size();
    biginteger zero(0);
    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto q = dlog->getOrder();
	map<int, vector<shared_ptr<AsymmetricCiphertext>>> cipherMap;
    #pragma omp parallel for schedule(static,1)
	for(size_t i = 0; i<rowLen ; i++){
        auto vectM = generateVectBigintFixed_parallel(q, zero, maxNFQ.at(i));
        auto vectR = generateVectBigintRand_parallel(q, maxNFQ.at(i));
		cipherMap[i] = generateVectElGamalCiphersFromVects_parallel(configFile, curve, pubKey, vectM, vectR);
	}
	return cipherMap;
}

map<int, vector<shared_ptr<AsymmetricCiphertext>>> encryptRowsFromLLR_parallel(string dir, string configFile, string curve , shared_ptr<PublicKey> pubKey, vector<int> vectQuantizedSample){
    
    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
	auto q = dlog->getOrder();
    map<int, vector<shared_ptr<AsymmetricCiphertext>>> cipherMap;
    size_t numFeatures = vectQuantizedSample.size();

    #pragma omp parallel for schedule(static,1)
	for(size_t i = 0; i<numFeatures ; i++){   
        auto llr = readRowfromHELRFile(dir, i, vectQuantizedSample.at(i));     
        auto vectR = generateVectBigintRand_parallel(q, llr.size());
		cipherMap[i] = generateVectElGamalCiphersFromVects_parallel(configFile, curve, pubKey, llr, vectR);
	}
	return cipherMap;
}

map<int, vector<Component>> generatePartialTemplate_parallel(biginteger userId, map<int, vector<int>> permutation, map<int, vector<shared_ptr<AsymmetricCiphertext>>> colEncMap, map<int, vector<shared_ptr<AsymmetricCiphertext>>> scoreEncMap){

	map<int, vector<Component>> temp;
	size_t sizeTemp = permutation.size();

    #pragma omp parallel for schedule(static,1)
	for(size_t i = 0; i<sizeTemp; i++){
		auto colLen = permutation[i].size();
        vector<Component> compVect;
        compVect.resize(colLen);
		for(size_t j = 0; j<colLen; j++){
            auto pos = permutation[i].at(j);
			auto index = userId + biginteger( (unsigned int) pos);
			compVect.at(pos) = Component(userId, index, colEncMap[i].at(j), scoreEncMap[i].at(j));
		}
        temp[i] = compVect;
	}

	return temp;
}

vector<shared_ptr<AsymmetricCiphertext>> extractColEncFromTemp_parallel(vector<Component> vectComp){

	vector<shared_ptr<AsymmetricCiphertext>> colEncVect;
    size_t len = vectComp.size();
	colEncVect.resize(len);
    #pragma omp parallel for schedule(static,1)
	for(size_t i = 0 ; i<len ; i++){
		colEncVect.at(i) = vectComp.at(i).colEnc;
	}

	return colEncVect;
}

vector<shared_ptr<AsymmetricCiphertext>> extractScoreEncFromTemp_parallel(vector<Component> vectComp){
	vector<shared_ptr<AsymmetricCiphertext>> scoreEncVect;
    size_t  len = vectComp.size();
	scoreEncVect.resize(len);
    #pragma omp parallel for schedule(static,1)
	for(size_t i = 0 ; i<len ; i++){
		scoreEncVect.at(i) = vectComp.at(i).scoreEnc;
	}
	return scoreEncVect;
}

map<int, vector<Component>> generateTemplate_parallel(string configFile, string curve, shared_ptr<GroupElement> verKey, biginteger signKey, map<int, vector<Component>> partialTemplate){
	map<int, vector<Component>> finalTemp; 	
	size_t sizeTemp = partialTemplate.size();

    #pragma omp parallel for schedule(static,1)
	for(size_t i = 0; i<sizeTemp; i++){ 
		auto colLen = partialTemplate[i].size();
        vector<Component> compVect;
        compVect.resize(colLen);
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        SchnorrSignature schnorr(dlog);
        schnorr.setKey(verKey, signKey); 
		for(size_t j = 0; j<colLen; j++){                        
			auto comp = partialTemplate[i].at(j);
			comp.signColEnc(schnorr);
			comp.signScoreEnc(schnorr);
			compVect.at(j) = Component(comp);
		}
        finalTemp[i] = compVect;
	}
	return finalTemp;
}

// bool verifyVectCompSignatures_parallel(string configFile, string curve, shared_ptr<GroupElement> verKey, vector<Component> vectComp){

//     size_t len = vectComp.size();
// 	vector<bool> result(2*len, true); 
//     #pragma omp parallel for schedule(static,1)
// 	for(size_t i = 0; i < len; i++){
//         auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
//         SchnorrSignature schnorr(dlog);
//         schnorr.setVerifKey(verKey);
//         result.at(i) = vectComp.at(i).verifyColEncSig(schnorr);
//         result.at(i+len) = vectComp.at(i).verifyScoreEncSig(schnorr);
// 	}
// 	return (find(result.begin(), result.end(), false) == result.end());
// }

bool verifyVectCompSignatures_parallel(string configFile, string curve, shared_ptr<GroupElement> verKey, vector<Component> vectComp){
    size_t len = vectComp.size();
    bool result = true;
    #pragma omp parallel for schedule(static,2) reduction(&& : result)
	for(size_t i = 0; i < len; i++){
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        SchnorrSignature schnorr(dlog);
        schnorr.setVerifKey(verKey);
        result = result && vectComp.at(i).verifyColEncSig(schnorr) && vectComp.at(i).verifyScoreEncSig(schnorr);
	}
    return result;
}

vector<shared_ptr<AsymmetricCiphertext>> subtractTwoCipherVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher1, vector<shared_ptr<AsymmetricCiphertext>> vectCipher2){

	vector<shared_ptr<AsymmetricCiphertext>> subtractedCipherVect;
    auto len = vectCipher1.size();
    subtractedCipherVect.resize(len);
    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);
        elgamal->setKey(pubKey);
        subtractedCipherVect.at(i) = subtractTwoCipher(dlog, elgamal, vectCipher1.at(i), vectCipher2.at(i));
    }

	return subtractedCipherVect;
}


vector<shared_ptr<AsymmetricCiphertext>> multEvenCipherVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher){

    vector<shared_ptr<AsymmetricCiphertext>> vect;
	biginteger zero(0);
    size_t len = vectCipher.size();
    len = len/2; 
    vect.resize(len);
    #pragma omp parallel for schedule(static,1)              
    for(size_t i = 0; i < len; i++){
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);
        elgamal->setKey(pubKey); 
        vect.at(i) = elgamal->multiply(vectCipher.at(i).get(),vectCipher.at(len+i).get(), zero);
    }
    return vect;
}


vector<shared_ptr<AsymmetricCiphertext>> multOddCipherVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher){

    vector<shared_ptr<AsymmetricCiphertext>> vect, vCipher;
	biginteger zero(0);
    vCipher = vectCipher;
    size_t len = vCipher.size();    
    if(len == 3){
        auto v = vCipher.at(len-1);
        vCipher.pop_back();
        vect = multEvenCipherVect_parallel(configFile, curve, pubKey, vCipher);
        vect.push_back(v);
        return multEvenCipherVect_parallel(configFile, curve, pubKey, vect);
    }

    auto v = vCipher.at(len-1);
    vCipher.pop_back();
    vect = multEvenCipherVect_parallel(configFile, curve, pubKey, vCipher);
    vect.push_back(v);

    return vect;
}



shared_ptr<AsymmetricCiphertext> multiplyCiphersOfVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, const vector<shared_ptr<AsymmetricCiphertext>>& vectCipher){
    vector<shared_ptr<AsymmetricCiphertext>> finalScore = vectCipher;
    vector<shared_ptr<AsymmetricCiphertext>> vect; 
    size_t len = finalScore.size();
    while(len > 1){        
        if((len % 2) == 1){
            vect.resize(0);
            vect = multOddCipherVect_parallel(configFile, curve, pubKey, finalScore);
            finalScore.resize(0);
            finalScore.insert(finalScore.end(), vect.begin(), vect.end()); 
            
        } else if((len % 2) == 0){
            vect.resize(0);
            vect = multEvenCipherVect_parallel(configFile, curve, pubKey, finalScore);
            finalScore.resize(0);
            finalScore.insert(finalScore.end(), vect.begin(), vect.end());            
        }  
        len = finalScore.size();     
    }
    return finalScore.at(0);
}

vector<shared_ptr<AsymmetricCiphertext>> subtractOneCipherFromCipherVect_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, shared_ptr<AsymmetricCiphertext> cipher){

	vector<shared_ptr<AsymmetricCiphertext>> subtractedCipherVect;
    auto len = vectCipher.size();
    subtractedCipherVect.resize(len);
    #pragma omp parallel for schedule(static,1)  
    for (size_t i = 0; i < len; i++)
    {   
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);
        elgamal->setKey(pubKey); 
        subtractedCipherVect.at(i) = subtractTwoCipher(dlog, elgamal, vectCipher.at(i), cipher);
    }

	return subtractedCipherVect;
}

bool finalDecryptionANDMatch_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, shared_ptr<PrivateKey> privKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipherBlinded, vector<shared_ptr<GroupElement>> vectPartialDec){
    auto vectU = getVectC1(vectCipherBlinded);
    size_t len = vectCipherBlinded.size();
    vector<bool> result(len, false);
	#pragma omp parallel for schedule(static,1) 
    for(size_t i = 0; i<len ; i++){
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);
        elgamal->setKey(pubKey, privKey);
        auto cipherF = ElGamalOnGroupElementCiphertext(vectU.at(i), vectPartialDec.at(i));
        shared_ptr<AsymmetricCiphertext> cipherFinal = make_shared<ElGamalOnGroupElementCiphertext>(cipherF);
        auto plainF = elgamal->decrypt(cipherFinal.get()); 
        auto gpElt = dynamic_cast<GroupElementPlaintext*>(plainF.get())->getElement();
        if(gpElt->isIdentity()){
            cout << "plainF = " << gpElt->generateSendableData()->toString() << endl;
            result.at(i) = true;
        }
    }
    return (find(result.begin(), result.end(), true) != result.end());
}

vector<shared_ptr<GroupElement>> getVectC1_parallel(vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
	vector<shared_ptr<GroupElement>> vectU;
    auto len = vectCipher.size();
    vectU.resize(len);
    
    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        auto cipher = dynamic_cast<ElGamalOnGroupElementCiphertext*>(vectCipher.at(i).get());
        vectU.at(i) = cipher->getC1();
    }
	return vectU;
}

vector<shared_ptr<GroupElement>> getVectC2_parallel(vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
	vector<shared_ptr<GroupElement>> vectV;
    auto len = vectCipher.size();
    vectV.resize(len);
    
    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        auto cipher = dynamic_cast<ElGamalOnGroupElementCiphertext*>(vectCipher.at(i).get());
        vectV.at(i) = cipher->getC2();
    }
	return vectV;
}

vector<shared_ptr<AsymmetricCiphertext>> blindVectCipherElGamal_parallel(string configFile, string curve, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<biginteger> rBlindVect){
	vector<shared_ptr<AsymmetricCiphertext>> blindedVect;
	size_t len = vectCipher.size();
    blindedVect.resize(len);
    #pragma omp parallel for schedule(static,1)
	for(size_t i = 0; i < len; i++){
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
		blindedVect.at(i) = blindCipherElGamal(dlog, vectCipher.at(i), rBlindVect.at(i));
	}
	return blindedVect;
}

vector<shared_ptr<GroupElement>> partiallyDecryptVectCiphers_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, shared_ptr<PrivateKey> privKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){

	vector<shared_ptr<GroupElement>> partialDecVect;
    auto len = vectCipher.size();
    partialDecVect.resize(len);
    #pragma omp parallel for schedule(static,1) 
	for(size_t i = 0; i < len; i++){

        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);
        elgamal->setKey(pubKey, privKey);
		auto partCipher = elgamal->decrypt(vectCipher.at(i).get());
 		auto partialCipher = dynamic_cast<GroupElementPlaintext*>(partCipher.get())->getElement();
		partialDecVect.at(i) = partialCipher;
	}
	return partialDecVect;
}

vector<shared_ptr<AsymmetricCiphertext>> elgamalPartialDecryption_parallel(string configFile, string curve, shared_ptr<PublicKey> pubKey, shared_ptr<PrivateKey> privKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){

	auto vectPartialDec = partiallyDecryptVectCiphers_parallel(configFile, curve, pubKey, privKey, vectCipher);
    auto vectU = getVectC1_parallel(vectCipher);
    size_t len = vectCipher.size();

	vector<shared_ptr<AsymmetricCiphertext>> vect;	
    vect.resize(len);

	#pragma omp parallel for schedule(static,1) 
	for(size_t i = 0; i<len ; i++){
		auto cipherF = ElGamalOnGroupElementCiphertext(vectU.at(i), vectPartialDec.at(i));
        shared_ptr<AsymmetricCiphertext> cipherFinal = make_shared<ElGamalOnGroupElementCiphertext>(cipherF);
		vect.at(i) = cipherFinal;
	}
	return vect;
}


vector<shared_ptr<AsymmetricCiphertext>> generateThresholdEncSet_parallel(int seed, string configFile, string curve, shared_ptr<PublicKey> pubKey, biginteger T, size_t len){
	vector<shared_ptr<AsymmetricCiphertext>> thresholdEncSet;
	srand(seed + time(0));
    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
	auto g = dlog->getGenerator();
    auto random = get_seeded_prg();
	auto q = dlog->getOrder();
    //auto qMinusOne = dlog->getOrder() - (biginteger)1;

    vector<biginteger> vectT;
	vectT.resize(len);
    #pragma omp parallel for schedule(static,1)
    for(int i = 0 ; i<len ; i++){
        vectT.at(i) = T+i;
    }

    shuffle(vectT.begin(), vectT.end(), default_random_engine(rand()));

    thresholdEncSet.resize(len);
    #pragma omp parallel for schedule(static,1)
    for(size_t i = 0; i<len ; i++){

        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);
        elgamal->setKey(pubKey);
        auto r = getRandomInRange(1, q-1, random.get());
        auto gPowT = dlog->exponentiate(g.get(), vectT.at(i));
        thresholdEncSet.at(i) = elgamal->encrypt(make_shared<GroupElementPlaintext>(gPowT), r);
    }
	return thresholdEncSet;
}




















/* 
* ZKs parallel [Prover]
*/


int zkPoKMultiANDPlainProver_parallel(shared_ptr<CommParty> prover, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<biginteger> vectM, vector<biginteger> vectR){
    // cout << "Run zkPoKMultiANDPlainProver ..." << endl;
    
    auto random = get_seeded_prg();
    auto count = vectM.size();

    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);

    auto h = dynamic_cast<ElGamalPublicKey*>(pubKey.get())->getH();
    shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenTrapdoorReceiver>(prover, dlog);
    
    // Receive commitment on challenge
    auto commitment = receiver->receiveCommitment();
    auto comId = commitment->getCommitmentId();   

    /* 
    *  Send Frist msg:      [Group Elt]  msgU = g^rForR
    *                       [Group Elt]  msgV = g^rForM * h^rForR   
    */

    vector<biginteger> vectRForR, vectRForM;
    vector<shared_ptr<GroupElement>> vectMsgU, vectMsgV;

    vectRForR.resize(count);
    vectRForM.resize(count);
    vectMsgU.resize(count);
    vectMsgV.resize(count);

    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < count; i++)
    {   
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        auto g = dlog->getGenerator();
        auto q = dlog->getOrder();

        vectRForR.at(i) = getRandomInRange(1, q - 1, random.get());
        vectRForM.at(i) = getRandomInRange(1, q - 1, random.get());

        vectMsgU.at(i) = dlog->exponentiate(g.get(), vectRForR.at(i));

        auto msgV1 = dlog->exponentiate(g.get(), vectRForM.at(i));
        auto msgV2 = dlog->exponentiate(h.get(), vectRForR.at(i));
        vectMsgV.at(i) = dlog->multiplyGroupElements(msgV1.get(), msgV2.get());

    }

    sendVectGpElt(prover, vectMsgU);
    sendVectGpElt(prover, vectMsgV);

    // Receive Decommitment and send the Trapdoor
    auto comm = receiver->receiveDecommitment(comId);
    if (comm == NULL) {
        cout << "commitment failed" << endl;
        return 0;
    }

    /* 
    * Send Second msg:
    *                       [Biginteger] msgZForR= rForR + challenge * r 
    *                       [Biginteger] msgZForM= rForM + challenge * m 
    */
    auto chall = comm->toString();
    biginteger challenge(chall);

    vector<biginteger> vectMsgZForR, vectMsgZForM; 
    vectMsgZForR.resize(count);   
    vectMsgZForM.resize(count);   

    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < count; i++)
    {
        vectMsgZForR.at(i) = vectRForR.at(i) + challenge * vectR.at(i);
        vectMsgZForM.at(i) = vectRForM.at(i) + challenge * vectM.at(i);
    }         

    sendVectBigint(prover, vectMsgZForR);
    sendVectBigint(prover, vectMsgZForM);

    // cout << "END zkPoKMultiANDPlainProver ..." << endl;
    return 1;
}


int niZKMultiANDDecZeroProver_parallel(shared_ptr<CommParty> prover, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, biginteger x){

    // cout << "Run niZKMultiANDDecZeroProver ..." << endl;
    
    auto random = get_seeded_prg();
    auto count = vectCipher.size();

    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto h = dynamic_cast<ElGamalPublicKey*>(pubKey.get())->getH();
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();

    auto vectU = getVectC1_parallel(vectCipher);

    /* 
    *       Frist msg:      [Group Elt]  msgU = g^rForR
    *                       [Group Elt]  msgV = u^rForR  
    */

    vector<biginteger> rForRVect;
    vector<shared_ptr<GroupElement>> msgUVect, msgVVect;
    vector<shared_ptr<GroupElement>> vectGpElt;

    rForRVect.resize(count);
    msgUVect.resize(count);
    msgVVect.resize(count);

    vectGpElt.resize(1 + 2*count);

    vectGpElt.at(0) = h;

    #pragma omp parallel for schedule(static,1)
    for(size_t i = 0 ; i < count ; i++){

        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        rForRVect.at(i) = getRandomInRange(1, q - 1, random.get());
        msgUVect.at(i) = dlog->exponentiate(g.get(),  rForRVect.at(i));
        vectGpElt.at(i+1) = msgUVect.at(i);
        msgVVect.at(i) = dlog->exponentiate(vectU.at(i).get(), rForRVect.at(i));
        vectGpElt.at(i+count+1) = msgVVect.at(i);
    }
    
    sendVectGpElt(prover, msgUVect);
    sendVectGpElt(prover, msgVVect);

    /* 
    *   Challenge = Hash( h, msgUVect, msgVVect ) 
    */

    auto challenge = generateChallenge(vectGpElt, q);

    /* 
    *       Second msg:              [Biginteger] msgZ= rForR + challenge * x   
    */
    vector<biginteger> msgZVect;
    msgZVect.resize(count);

    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < count; i++)
    {
        msgZVect.at(i) = (rForRVect.at(i) + challenge * x) % q;
    }
    

 
    sendVectBigint(prover, msgZVect);
    
    auto str = receiveStr(prover);
    // cout << "END niZKMultiANDDecZeroProver ..." << endl;
    return ((str == "Success") ? 1 : 0);
}

int niZKMultiANDBlindedProver_parallel(shared_ptr<CommParty> prover, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<biginteger> rBlindVect){
    // cout << "Run niZKMultiANDBlindedProver ..." << endl;
    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);    
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto len = vectCipher.size();
    
    auto h = dynamic_cast<ElGamalPublicKey*>(pubKey.get())->getH();

    auto vectU = getVectC1_parallel(vectCipher);
    auto vectV = getVectC2_parallel(vectCipher);


    vector<biginteger> rForRVect;
    vector<shared_ptr<GroupElement>> msgUVect, msgVVect;
    rForRVect.resize(len);
    msgUVect.resize(len);
    msgVVect.resize(len);

    #pragma omp parallel for schedule(static,1)
    for(size_t i = 0 ; i < len ; i++){
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        rForRVect.at(i) = getRandomInRange(1, q - 1, random.get());
        msgUVect.at(i) = dlog->exponentiate(vectU.at(i).get(), rForRVect.at(i));
        msgVVect.at(i) = dlog->exponentiate(vectV.at(i).get(), rForRVect.at(i));             
    }

    sendVectGpElt(prover, msgUVect);
    sendVectGpElt(prover, msgVVect);

    // Challenge = Hash( h, msgU, msgV )
    vector<shared_ptr<GroupElement>> vectGpElt;
    vectGpElt.resize(2*len+1);
    vectGpElt.at(0) = h;

    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        vectGpElt.at(1+i) = msgUVect.at(i);
        vectGpElt.at(len+1+i) = msgVVect.at(i);
    }   
    auto challenge = generateChallenge(vectGpElt, q);

    vector<biginteger> msgZVect;
    msgZVect.resize(len);
    #pragma omp parallel for schedule(static,1)
    for(int i = 0 ; i<len ; i++){
        msgZVect.at(i) = (rForRVect.at(i) + challenge * rBlindVect.at(i)) % q;
    }

    sendVectBigint(prover, msgZVect);

    auto str = receiveStr(prover);
    // cout << "END niZKMultiANDBlindedProver ..." << endl;
    return ((str == "Success") ? 1 : 0);
}


int niZKMultiANDPartialDecProver_parallel(shared_ptr<CommParty> prover, string configFile, string curve, shared_ptr<PublicKey> provThreshPubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, biginteger provPrivKey){
    // cout << "Run niZKMultiANDPartialDecProver ..." << endl;
    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();
    auto count = vectCipher.size();

    auto vectU = getVectC1_parallel(vectCipher);
    auto provPK = dynamic_cast<ElGamalPublicKey*>(provThreshPubKey.get())->getH();

    vector<biginteger> rForRVect; 
    vector<shared_ptr<GroupElement>> msgUVect, msgVVect;
    rForRVect.resize(count);
    msgUVect.resize(count);
    msgVVect.resize(count);


    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < count; i++)
    {
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
        rForRVect.at(i) = getRandomInRange(1, q - 1, random.get());
        msgUVect.at(i) = dlog->exponentiate(g.get(), rForRVect.at(i));
        msgVVect.at(i) = dlog->exponentiate(vectU.at(i).get(), rForRVect.at(i)); 
    }

    sendVectGpElt(prover, msgUVect);
    sendVectGpElt(prover, msgVVect);



    vector<shared_ptr<GroupElement>> vectGpElt;
    vectGpElt.resize(1+2*count);
    vectGpElt.at(0) = provPK;

    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < count; i++)
    {
        vectGpElt.at(i+1) = msgUVect.at(i);
        vectGpElt.at(i+count+1) = msgVVect.at(i);
    }    
    auto challenge = generateChallenge(vectGpElt, q);

    vector<biginteger> msgZVect;
    msgZVect.resize(count);

    #pragma omp parallel for schedule(static,1)
    for(int i = 0 ; i<count ; i++){
        msgZVect.at(i) = (rForRVect.at(i) + challenge * provPrivKey) % q;
    }

    sendVectBigint(prover, msgZVect);  

    auto str = receiveStr(prover);
    // cout << "END niZKMultiANDPartialDecProver ..." << endl;
    return ((str == "Success") ? 1 : 0);
}














/* 
* ZKs parallel [Verifier]
*/



bool zkPoKMultiANDPlainVerifier_parallel(shared_ptr<CommParty> verifier, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){

    // cout << "Run zkPoKMultiANDPlainVerifier ..." << endl;

    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto g = dlog->getGenerator();

    auto count = vectCipher.size();

    shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenTrapdoorCommitter>(verifier, dlog);    
        
    /* Commit on the challenge */
    long valId = 0;
    auto val = committer->sampleRandomCommitValue(); 
    biginteger challenge(val->toString());
    committer->commit(val, valId);

    auto h = dynamic_cast<ElGamalPublicKey*>(pubKey.get())->getH();

    auto vectU = getVectC1_parallel(vectCipher);
    auto vectV = getVectC2_parallel(vectCipher);

    /* 
    * Receive      
    *       
    *       Frist msg:      [Group Elt]  msgU
    *                       [Group Elt]  msgV   
    */

    auto vectMsgU = receiveVectGpElt(verifier, dlog);
    auto vectMsgV = receiveVectGpElt(verifier, dlog);

    // Decommit on the challenge
    committer->decommit(valId);

    /* 
    * Receive and Verify      
    *       
    *       Second msg:
    *                       1) g^msgZForR =? msgU * u^challenge
    *                       2) g^msgZForM * h^msgZForR =? msgV * v^challenge
    */

    auto vectMsgZForR = receiveVectBigint(verifier);
    auto vectMsgZForM = receiveVectBigint(verifier);



/*     vector<bool> result(count, true); 
    
    #pragma omp parallel for schedule(static,1) 
    for (size_t i = 0; i < count; i++){

        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);

        auto verify1Part1 = dlog->exponentiate(g.get(), vectMsgZForR.at(i));
        auto gPowMsgZForM = dlog->exponentiate(g.get(), vectMsgZForM.at(i));
        auto hPowMsgZForR = dlog->exponentiate(h.get(), vectMsgZForR.at(i));
        auto verify2Part1 = dlog->multiplyGroupElements(gPowMsgZForM.get(), hPowMsgZForR.get());

        auto uPowChallenge = dlog->exponentiate(vectU.at(i).get(), challenge);
        auto vPowChallenge = dlog->exponentiate(vectV.at(i).get(), challenge);

        auto verify1Part2 = dlog->multiplyGroupElements(vectMsgU.at(i).get(), uPowChallenge.get());
        auto verify2Part2 = dlog->multiplyGroupElements(vectMsgV.at(i).get(), vPowChallenge.get());

        
        bool verify1 = areEqual(verify1Part1, verify1Part2);
        bool verify2 = areEqual(verify2Part1, verify2Part2);

        result.at(i) = (verify1 && verify2);
    }
    bool res = (find(result.begin(), result.end(), false) == result.end()); */

    bool result = true;     
    #pragma omp parallel for schedule(static,1) reduction(&& : result)
    for (size_t i = 0; i < count; i++){

        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);

        auto verify1Part1 = dlog->exponentiate(g.get(), vectMsgZForR.at(i));
        auto gPowMsgZForM = dlog->exponentiate(g.get(), vectMsgZForM.at(i));
        auto hPowMsgZForR = dlog->exponentiate(h.get(), vectMsgZForR.at(i));
        auto verify2Part1 = dlog->multiplyGroupElements(gPowMsgZForM.get(), hPowMsgZForR.get());

        auto uPowChallenge = dlog->exponentiate(vectU.at(i).get(), challenge);
        auto vPowChallenge = dlog->exponentiate(vectV.at(i).get(), challenge);

        auto verify1Part2 = dlog->multiplyGroupElements(vectMsgU.at(i).get(), uPowChallenge.get());
        auto verify2Part2 = dlog->multiplyGroupElements(vectMsgV.at(i).get(), vPowChallenge.get());

        result = result && areEqual(verify1Part1, verify1Part2) && areEqual(verify2Part1, verify2Part2);
    }

    // cout << "END zkPoKMultiANDPlainVerifier ..." << endl;
    return result;
}




bool niZKMultiANDBlindedVerifier_parallel(shared_ptr<CommParty> verifier, string configFile, string curve, shared_ptr<PublicKey> pubKey,
 vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<shared_ptr<AsymmetricCiphertext>> vectBlindedCipher){
    // cout << "Run niZKMultiANDBlindedVerifier ..." << endl;

    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto q = dlog->getOrder();

    auto h = dynamic_cast<ElGamalPublicKey*>(pubKey.get())->getH();

    auto vectU = getVectC1_parallel(vectCipher);
    auto vectV = getVectC2_parallel(vectCipher);
    auto vectA = getVectC1_parallel(vectBlindedCipher);
    auto vectB = getVectC2_parallel(vectBlindedCipher);

    auto msgUVect = receiveVectGpElt(verifier, dlog);     
    auto msgVVect = receiveVectGpElt(verifier, dlog); 
    auto msgZVect = receiveVectBigint(verifier);

    auto len = vectCipher.size();

    // Challenge = Hash( h, msgU, msgV )
    vector<shared_ptr<GroupElement>> vectGpElt;
    vectGpElt.resize(1+2*len);
    vectGpElt.at(0) = h;

    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        vectGpElt.at(i+1) = msgUVect.at(i);
        vectGpElt.at(i+len+1) = msgVVect.at(i);
    }
    
    
    auto challenge = generateChallenge(vectGpElt, q);

    /* vector<bool> result(len, true); 
    
    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);

        auto verify1Part1 = dlog->exponentiate(vectU.at(i).get(), msgZVect.at(i));
        auto aPowChallenge = dlog->exponentiate(vectA.at(i).get(), challenge);
        auto verify1Part2 = dlog->multiplyGroupElements(msgUVect.at(i).get(), aPowChallenge.get());

        auto verify2Part1 = dlog->exponentiate(vectV.at(i).get(), msgZVect.at(i));
        auto bPowChallenge = dlog->exponentiate(vectB.at(i).get(), challenge);
        auto verify2Part2 = dlog->multiplyGroupElements(msgVVect.at(i).get(), bPowChallenge.get());

        bool verify1 = areEqual(verify1Part1, verify1Part2);
        bool verify2 = areEqual(verify2Part1, verify2Part2);

        result.at(i) = (verify1 && verify2);
    }
    
    bool res = (find(result.begin(), result.end(), false) == result.end());

    (res ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));
    */
    
    /* bool result = true;    
    #pragma omp parallel for schedule(static,1) reduction(&& : result)
    for (size_t i = 0; i < len; i++)
    {
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);

        auto verify1Part1 = dlog->exponentiate(vectU.at(i).get(), msgZVect.at(i));
        auto aPowChallenge = dlog->exponentiate(vectA.at(i).get(), challenge);
        auto verify1Part2 = dlog->multiplyGroupElements(msgUVect.at(i).get(), aPowChallenge.get());

        auto verify2Part1 = dlog->exponentiate(vectV.at(i).get(), msgZVect.at(i));
        auto bPowChallenge = dlog->exponentiate(vectB.at(i).get(), challenge);
        auto verify2Part2 = dlog->multiplyGroupElements(msgVVect.at(i).get(), bPowChallenge.get());

        result = result && areEqual(verify1Part1, verify1Part2) && areEqual(verify2Part1, verify2Part2);
    } */


    shared_ptr<GroupElement> u, v, a, b, msgU, msgV;
    biginteger msgZ;
    bool result = true;

    BOOST_FOREACH(boost::tie(u, v, a, b, msgU, msgV, msgZ), boost::combine(vectU, vectV, vectA, vectB, msgUVect, msgVVect, msgZVect)){

        auto verify1Part1 = dlog->exponentiate(u.get(), msgZ);
        auto aPowChallenge = dlog->exponentiate(a.get(), challenge);
        auto verify1Part2 = dlog->multiplyGroupElements(msgU.get(), aPowChallenge.get());

        auto verify2Part1 = dlog->exponentiate(v.get(), msgZ);
        auto bPowChallenge = dlog->exponentiate(b.get(), challenge);
        auto verify2Part2 = dlog->multiplyGroupElements(msgV.get(), bPowChallenge.get());

        bool verify1 = areEqual(verify1Part1, verify1Part2);
        bool verify2 = areEqual(verify2Part1, verify2Part2);

        result = result && (verify1 && verify2);

    }


    (result ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));
    // cout << "END niZKMultiANDBlindedVerifier ..." << endl;
    return result;
}

bool niZKMultiANDPartialDecVerifier_parallel(shared_ptr<CommParty> verifier, string configFile, string curve, shared_ptr<PublicKey> provThreshPubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<shared_ptr<GroupElement>> partialCipherVect){
    // cout << "Run niZKMultiANDPartialDecVerifier ..." << endl;
    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto q = dlog->getOrder();
    auto g = dlog->getGenerator();
	size_t len = vectCipher.size();

    auto provPK = dynamic_cast<ElGamalPublicKey*>(provThreshPubKey.get())->getH();

    auto vectU = getVectC1_parallel(vectCipher);
    auto vectV = getVectC2_parallel(vectCipher);

    
    auto msgUVect = receiveVectGpElt(verifier, dlog);
    auto msgVVect = receiveVectGpElt(verifier, dlog);
    auto msgZVect = receiveVectBigint(verifier);

    // Challenge = Hash( jointPK, msgU, msgV )

    vector<shared_ptr<GroupElement>> vectGpElt;
    vectGpElt.resize(1+2*len);
    vectGpElt.at(0) = provPK;

    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        vectGpElt.at(i+1) = msgUVect.at(i);
        vectGpElt.at(i+len+1) = msgVVect.at(i);
    }    
    auto challenge = generateChallenge(vectGpElt, q);

    
    auto provPKPowChallenge = dlog->exponentiate(provPK.get(), challenge);


/*     vector<bool> result(len, true); 
    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);

        auto verify1Part1 = dlog->exponentiate(g.get(), msgZVect.at(i));
        auto verify1Part2 = dlog->multiplyGroupElements(msgUVect.at(i).get(), provPKPowChallenge.get());

        auto verify2Part1 = dlog->exponentiate(vectU.at(i).get(), msgZVect.at(i));
        auto invPartCipher = dlog->getInverse(partialCipherVect.at(i).get());
        auto vMultInvPartCipher = dlog->multiplyGroupElements(vectV.at(i).get(),invPartCipher.get());
        auto vInvPrtCiphPowChallenge = dlog->exponentiate(vMultInvPartCipher.get(), challenge);
        auto verify2Part2 = dlog->multiplyGroupElements(msgVVect.at(i).get(), vInvPrtCiphPowChallenge.get());


        bool verify1 = areEqual(verify1Part1, verify1Part2);
        bool verify2 = areEqual(verify2Part1, verify2Part2);

        result.at(i) = (verify1 && verify2);
    }    
    bool res = (find(result.begin(), result.end(), false) == result.end());

    (res ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure")); */

    bool result = true; 
    #pragma omp parallel for schedule(static,1) reduction(&& : result)
    for (size_t i = 0; i < len; i++)
    {
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);

        auto verify1Part1 = dlog->exponentiate(g.get(), msgZVect.at(i));
        auto verify1Part2 = dlog->multiplyGroupElements(msgUVect.at(i).get(), provPKPowChallenge.get());

        auto verify2Part1 = dlog->exponentiate(vectU.at(i).get(), msgZVect.at(i));
        auto invPartCipher = dlog->getInverse(partialCipherVect.at(i).get());
        auto vMultInvPartCipher = dlog->multiplyGroupElements(vectV.at(i).get(),invPartCipher.get());
        auto vInvPrtCiphPowChallenge = dlog->exponentiate(vMultInvPartCipher.get(), challenge);
        auto verify2Part2 = dlog->multiplyGroupElements(msgVVect.at(i).get(), vInvPrtCiphPowChallenge.get());

        result = result && areEqual(verify1Part1, verify1Part2) && areEqual(verify2Part1, verify2Part2);
    }    


    (result ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));

    // cout << "END niZKMultiANDPartialDecVerifier ..." << endl;
    return result;
}

bool niZKMultiANDDecZeroVerifier_parallel(shared_ptr<CommParty> verifier, string configFile, string curve, shared_ptr<PublicKey> pubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
    // cout << "Run niZKMultiANDDecZeroVerifier ..." << endl;
    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    size_t len = vectCipher.size();

    auto h = dynamic_cast<ElGamalPublicKey*>(pubKey.get())->getH();

    auto vectU = getVectC1_parallel(vectCipher);
    auto vectV = getVectC2_parallel(vectCipher);
    
    auto msgUVect = receiveVectGpElt(verifier, dlog);     
    auto msgVVect = receiveVectGpElt(verifier, dlog);  

    auto msgZVect = receiveVectBigint(verifier); 

    // Challenge = Hash( h, msgU, msgV )
    vector<shared_ptr<GroupElement>> vectGpElt;
    vectGpElt.resize(1+2*len);
    vectGpElt.at(0) = h;

    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        vectGpElt.at(i+1) = msgUVect.at(i);
        vectGpElt.at(i+len+1) = msgVVect.at(i);
    } 
    auto challenge = generateChallenge(vectGpElt, q);
    auto hPowChallenge = dlog->exponentiate(h.get(), challenge);

/*     vector<bool> result(len, true); 
    #pragma omp parallel for schedule(static,1)
    for (size_t i = 0; i < len; i++)
    {
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);

        auto verify1Part1 = dlog->exponentiate(g.get(), msgZVect.at(i));        
        auto verify1Part2 = dlog->multiplyGroupElements(msgUVect.at(i).get(), hPowChallenge.get());

        auto verify2Part1 = dlog->exponentiate(vectU.at(i).get(), msgZVect.at(i));
        auto vPowChallenge = dlog->exponentiate(vectV.at(i).get(), challenge);
        auto verify2Part2 = dlog->multiplyGroupElements(msgVVect.at(i).get(), vPowChallenge.get());
        
        bool verify1 = areEqual(verify1Part1, verify1Part2);
        bool verify2 = areEqual(verify2Part1, verify2Part2);

        result.at(i) = (verify1 && verify2);
    }

    bool res = (find(result.begin(), result.end(), false) == result.end()); 
    (res ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure")); */


    bool result = true; 
    #pragma omp parallel for schedule(static,1) reduction(&& : result)
    for (size_t i = 0; i < len; i++)
    {
        auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);

        auto verify1Part1 = dlog->exponentiate(g.get(), msgZVect.at(i));        
        auto verify1Part2 = dlog->multiplyGroupElements(msgUVect.at(i).get(), hPowChallenge.get());

        auto verify2Part1 = dlog->exponentiate(vectU.at(i).get(), msgZVect.at(i));
        auto vPowChallenge = dlog->exponentiate(vectV.at(i).get(), challenge);
        auto verify2Part2 = dlog->multiplyGroupElements(msgVVect.at(i).get(), vPowChallenge.get());
        
        result = result && areEqual(verify1Part1, verify1Part2) && areEqual(verify2Part1, verify2Part2);
    }


    (result ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));


    
    // cout << "END niZKMultiANDDecZeroVerifier ..." << endl;
    return result;
}