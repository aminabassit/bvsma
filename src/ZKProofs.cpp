#include "bvsma/include/ZKProofs.hpp"


void ProverUsage(){
    std::cerr << "Usage: ./prover 8080 8081 zkProofTotest" << std::endl; 
}

void VerifierUsage(){
    std::cerr << "Usage: ./verifier 8081 8080 zkProofTotest" << std::endl; 
}


/******************************\
|**** Interactive ZKProofs ****|
\******************************/




/* Prover */



/* [Prover] Simple */

int zkPoKBasicProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<GroupElement> h, biginteger w){
    cout << "Run zkPoKBasicProver ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenTrapdoorReceiver>(prover, dlog);
    auto commitment = receiver->receiveCommitment();
    //receive Commitment on challenge
    auto comId = commitment->getCommitmentId();

    // Send First message:  msgA
    biginteger rForA = getRandomInRange(1, q-1, random.get());    
    auto msgA = dlog->exponentiate(g.get(), rForA);
    sendGpElt(prover, msgA);

    // Receive Decommitment and send the Trapdoor
    auto comm = receiver->receiveDecommitment(comId);
    if (comm == NULL) {
        cout << "Commitment has Failed" << endl;
        return 0;
    }

    // Send Second message: msgZ
    auto chall = comm->toString();
    biginteger challenge(chall);
    biginteger msgZ = rForA + challenge * w ;
    sendBigint(prover, msgZ);

    cout << "END zkPoKBasicProver ..." << endl;
    return 1;
}


int zkPoKSinglePlainProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, biginteger m, biginteger r){
    cout << "Run zkPoKSinglePlainProver ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();
    shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenTrapdoorReceiver>(prover, dlog);
    
    // Receive commitment on challenge
    auto commitment = receiver->receiveCommitment();
    auto comId = commitment->getCommitmentId();   

    /* 
    *  Send Frist msg:      [Group Elt]  msgU = g^rForR
    *                       [Group Elt]  msgV = g^rForM * h^rForR   
    */

    biginteger rForR = getRandomInRange(1, q - 1, random.get());
    biginteger rForM = getRandomInRange(1, q - 1, random.get());

    auto msgU = dlog->exponentiate(g.get(), rForR);
    auto msgV1 = dlog->exponentiate(g.get(), rForM);
    auto msgV2 = dlog->exponentiate(h.get(), rForR);
    auto msgV = dlog->multiplyGroupElements(msgV1.get(), msgV2.get());

    sendGpElt(prover, msgU);
    sendGpElt(prover, msgV);

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

    biginteger msgZForR = rForR + challenge * r;
    biginteger msgZForM = rForM + challenge * m;

    sendBigint(prover, msgZForR);
    sendBigint(prover, msgZForM);

    cout << "END zkPoKSinglePlainProver ..." << endl;
    return 1;
}






/* [Prover] Multiple AND */
int zkPoKMultiANDPlainProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<biginteger> vectM, vector<biginteger> vectR){
    cout << "Run zkPoKMultiANDPlainProver ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();
    auto count = vectM.size();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();
    shared_ptr<CmtReceiver> receiver = make_shared<CmtPedersenTrapdoorReceiver>(prover, dlog);
    
    // Receive commitment on challenge
    auto commitment = receiver->receiveCommitment();
    auto comId = commitment->getCommitmentId();   

    /* 
    *  Send Frist msg:      [Group Elt]  msgU = g^rForR
    *                       [Group Elt]  msgV = g^rForM * h^rForR   
    */

    biginteger rForR, rForM;
    vector<biginteger> vectRForR, vectRForM;
    shared_ptr<GroupElement> msgU, msgV1, msgV2, msgV;
    vector<shared_ptr<GroupElement>> vectMsgU, vectMsgV;

    for (size_t i = 0; i < count; i++)
    {
        rForR = getRandomInRange(1, q - 1, random.get());
        vectRForR.push_back(rForR);
        rForM = getRandomInRange(1, q - 1, random.get());
        vectRForM.push_back(rForM);

        msgU = dlog->exponentiate(g.get(), rForR);
        vectMsgU.push_back(msgU);
        msgV1 = dlog->exponentiate(g.get(), rForM);
        msgV2 = dlog->exponentiate(h.get(), rForR);
        msgV = dlog->multiplyGroupElements(msgV1.get(), msgV2.get());
        vectMsgV.push_back(msgV);
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

    biginteger msgZForR, msgZForM;
    vector<biginteger> vectMsgZForR, vectMsgZForM;    

    for (size_t i = 0; i < count; i++)
    {
        msgZForR = vectRForR.at(i) + challenge * vectR.at(i);
        vectMsgZForR.push_back(msgZForR);

        msgZForM = vectRForM.at(i) + challenge * vectM.at(i);
        vectMsgZForM.push_back(msgZForM);
    }         

    sendVectBigint(prover, vectMsgZForR);
    sendVectBigint(prover, vectMsgZForM);

    cout << "END zkPoKMultiANDPlainProver ..." << endl;
    return 1;
}






/* Verifier */


/* [Verifier] Simple */

bool zkPoKBasicVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<GroupElement> h){
    cout << "Run zkPoKBasicVerifier ..."<< endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenTrapdoorCommitter>(verifier, dlog);      
    long valId = 0;
    auto val = committer->sampleRandomCommitValue(); 
    // Send Commitment on challenge 
    committer->commit(val, valId);
    // Receive First message msgA
    auto msgA = receiveGpElt(verifier, dlog);  
    // Send Decommitment 
    committer->decommit(valId);
    // Receive Second message msgZ
    auto msgZ = receiveBigint(verifier);

    // Verify g^z =? A * h^val    
    auto gPowZ = dlog->exponentiate(g.get(), msgZ);    
    biginteger challenge(val->toString());
    auto hPowChall = dlog->exponentiate(h.get(),challenge);        
    auto msgA_Mul_hPowChall = dlog->multiplyGroupElements(msgA.get(),hPowChall.get());
    cout << "END zkPoKBasicVerifier ..." << endl;
    return areEqual(gPowZ, msgA_Mul_hPowChall);
}

bool zkPoKSinglePlainVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher){
    cout << "Run zkPoKSinglePlainVerifier ..."<< endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenTrapdoorCommitter>(verifier, dlog);    
        
    /* Commit on the challenge */

    long valId = 0;
    auto val = committer->sampleRandomCommitValue(); 
    biginteger challenge(val->toString());
    committer->commit(val, valId);

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    auto u = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC1();
    auto v = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC2();

    /* 
    * Receive    Frist msg:         [Group Elt]  msgU
    *                           	[Group Elt]  msgV   
    */

    auto msgU = receiveGpElt(verifier, dlog);
    auto msgV = receiveGpElt(verifier, dlog);

    // Decommit on the challenge
    committer->decommit(valId);

    /* 
    * Receive and Verify      
    *       
    *       Second msg:
    *                       1) g^msgZForR =? msgU * u^challenge
    *                       2) g^msgZForM * h^msgZForR =? msgV * v^challenge
    */

    auto msgZForR = receiveBigint(verifier);
    auto msgZForM = receiveBigint(verifier);
    
    auto verify1Part1 = dlog->exponentiate(g.get(), msgZForR);
    auto gPowMsgZForM = dlog->exponentiate(g.get(), msgZForM);
    auto hPowMsgZForR = dlog->exponentiate(h.get(), msgZForR);
    auto verify2Part1 = dlog->multiplyGroupElements(gPowMsgZForM.get(), hPowMsgZForR.get());

    auto uPowChallenge = dlog->exponentiate(u.get(), challenge);
    auto vPowChallenge = dlog->exponentiate(v.get(), challenge);

    auto verify1Part2 = dlog->multiplyGroupElements(msgU.get(), uPowChallenge.get());
    auto verify2Part2 = dlog->multiplyGroupElements(msgV.get(), vPowChallenge.get());

    bool verify1 = areEqual(verify1Part1, verify1Part2);
    bool verify2 = areEqual(verify2Part1, verify2Part2);

    cout << "END zkPoKSinglePlainVerifier ..." << endl;
    return (verify1 && verify2);
}




/* [Verifier] Multiple AND */
bool zkPoKMultiANDPlainVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
    cout << "Run zkPoKMultiANDPlainVerifier ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();
    auto count = vectCipher.size();

    shared_ptr<CmtCommitter> committer = make_shared<CmtPedersenTrapdoorCommitter>(verifier, dlog);    
        
    /* Commit on the challenge */
    long valId = 0;
    auto val = committer->sampleRandomCommitValue(); 
    biginteger challenge(val->toString());
    committer->commit(val, valId);

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    auto vectU = getVectC1(vectCipher);
    auto vectV = getVectC2(vectCipher);

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

    shared_ptr<GroupElement> verify1Part1, gPowMsgZForM, hPowMsgZForR, verify2Part1;
    shared_ptr<GroupElement> uPowChallenge, vPowChallenge, verify1Part2, verify2Part2;

    bool verify1, verify2, result = true;    

    for (size_t i = 0; i < count; i++){
        verify1Part1 = dlog->exponentiate(g.get(), vectMsgZForR.at(i));
        gPowMsgZForM = dlog->exponentiate(g.get(), vectMsgZForM.at(i));
        hPowMsgZForR = dlog->exponentiate(h.get(), vectMsgZForR.at(i));
        verify2Part1 = dlog->multiplyGroupElements(gPowMsgZForM.get(), hPowMsgZForR.get());

        uPowChallenge = dlog->exponentiate(vectU.at(i).get(), challenge);
        vPowChallenge = dlog->exponentiate(vectV.at(i).get(), challenge);

        verify1Part2 = dlog->multiplyGroupElements(vectMsgU.at(i).get(), uPowChallenge.get());
        verify2Part2 = dlog->multiplyGroupElements(vectMsgV.at(i).get(), vPowChallenge.get());

        verify1 = areEqual( verify1Part1, verify1Part2);
        verify2 = areEqual( verify2Part1, verify2Part2);
        //cout << "verify1 = " << verify1 << " verify2 = " << verify2 << endl;
        result = result && (verify1 && verify2);
    }

    //(result ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));
    cout << "END zkPoKMultiANDPlainVerifier ..." << endl;
    return result;
}




























/* ================================================================================================================================================================================ */











/**********************************\
|**** Non-Interactive ZKProofs ****|
\**********************************/



/* Prover */


/* [Prover] Simple */
int niZKDecZeroProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher, biginteger x){
    cout << "Run niZKDecZeroProver ..."<< endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    /* 
    * Send   Frist msg:      [Group Elt]  msgU = g^rForR
    *                        [Group Elt]  msgV = u^rForR  
    */
    auto rForR = getRandomInRange(1, q - 1, random.get());
    auto msgU = dlog->exponentiate(g.get(), rForR);

    auto u = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC1();
    auto msgV = dlog->exponentiate(u.get(), rForR);

    sendGpElt(prover, msgU);
    sendGpElt(prover, msgV);

    /* 
    *   Challenge = Hash( h, msgU, msgV ) 
    */
    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(h);
    vectGpElt.push_back(msgU);
    vectGpElt.push_back(msgV);
    
    auto challenge = generateChallenge(vectGpElt, q);

    /* 
    *   Send   Second msg:      [Biginteger] msgZ= rForR + challenge * x 
    */

    biginteger msgZ = (rForR + challenge * x) % q;
    sendBigint(prover, msgZ);

    auto str = receiveStr(prover);
    cout << "END niZKDecZeroProver ..." << endl;
    return ((str == "Success") ? 1 : 0);
}

int niZKBlindedProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher, biginteger rBlind){
    cout << "Run niZKBlindedProver ..."<< endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    auto u = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC1();
	auto v = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC2();

    /* 
    *       Frist msg:      [Group Elt]  msgU = u^rForR
    *                       [Group Elt]  msgV = v^rForR 
    */

    auto rForR = getRandomInRange(1, q - 1, random.get());
    auto msgU = dlog->exponentiate(u.get(), rForR);        
    auto msgV = dlog->exponentiate(v.get(), rForR);

    sendGpElt(prover, msgU);
    sendGpElt(prover, msgV);

    /* 
    *   Challenge = Hash( h, msgU, msgV ) 
    */

    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(h);
    vectGpElt.push_back(msgU);
    vectGpElt.push_back(msgV);
    
    auto challenge = generateChallenge(vectGpElt, q);

    /* 
    *       Second msg:              [Biginteger] msgZ= rForR + challenge * rBlind 
    */

    biginteger msgZ = (rForR + challenge * rBlind) % q;  
    sendBigint(prover, msgZ);

    auto str = receiveStr(prover);
    cout << "END niZKBlindedProver ..." << endl;
    return ((str == "Success") ? 1 : 0);
}

int niZKPartialDecProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<PublicKey> provThreshPubKey, shared_ptr<AsymmetricCiphertext> cipher, biginteger provPrivKey){
    cout << "Run niZKPartialDecProver ..."<< endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto provPK = dynamic_cast<ElGamalPublicKey*>(provThreshPubKey.get())->getH();
    auto u = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC1();

    /* 
    *       Frist msg:      [Group Elt]  msgU = g^rForR   and    msgV = u^rForR
    */


    auto rForR = getRandomInRange(1, q - 1, random.get());
    auto msgU = dlog->exponentiate(g.get(), rForR);        
    auto msgV = dlog->exponentiate(u.get(), rForR);

    sendGpElt(prover, msgU);
    sendGpElt(prover, msgV);

    /* 
    *   Challenge = Hash( provPK, msgU, msgV ) 
    */

    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(provPK);
    vectGpElt.push_back(msgU);
    vectGpElt.push_back(msgV);
    
    auto challenge = generateChallenge(vectGpElt, q);

    /* 
    *       Second msg:              [Biginteger] msgZ= rForR + challenge * provPrivKey  
    */

    biginteger msgZ = (rForR + challenge * provPrivKey) % q;
    sendBigint(prover, msgZ);

    auto str = receiveStr(prover);
    cout << "END niZKPartialDecProver ..." << endl;
    return ((str == "Success") ? 1 : 0);
}




/* [Prover] Multiple AND */

int niZKMultiANDDecZeroProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, biginteger x){

    cout << "Run niZKMultiANDDecZeroProver ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();
    auto count = vectCipher.size();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    auto vectU = getVectC1(vectCipher);

    /* 
    *       Frist msg:      [Group Elt]  msgU = g^rForR
    *                       [Group Elt]  msgV = u^rForR  
    */

    vector<biginteger> rForRVect;
    vector<shared_ptr<GroupElement>> msgUVect, msgVVect;

    for(size_t i = 0 ; i < count ; i++){
        rForRVect.push_back(getRandomInRange(1, q - 1, random.get()));
        msgUVect.push_back(dlog->exponentiate(g.get(),  rForRVect.at(i)));
        msgVVect.push_back(dlog->exponentiate(vectU.at(i).get(), rForRVect.at(i)));
    }
    
    sendVectGpElt(prover, msgUVect);
    sendVectGpElt(prover, msgVVect);

    /* 
    *   Challenge = Hash( h, msgUVect, msgVVect ) 
    */

    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(h);
    vectGpElt.insert(vectGpElt.end(), msgUVect.begin(), msgUVect.end());
    vectGpElt.insert(vectGpElt.end(), msgVVect.begin(), msgVVect.end());
    
    auto challenge = generateChallenge(vectGpElt, q);

    /* 
    *       Second msg:              [Biginteger] msgZ= rForR + challenge * x   
    */
    vector<biginteger> msgZVect;
    for(auto r : rForRVect){
        msgZVect.push_back((r + challenge * x) % q);
    }
 
    sendVectBigint(prover, msgZVect);
    
    auto str = receiveStr(prover);
    cout << "END niZKMultiANDDecZeroProver ..." << endl;
    return ((str == "Success") ? 1 : 0);
}

int niZKMultiANDBlindedProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<biginteger> rBlindVect){
    cout << "Run niZKMultiANDBlindedProver ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();
    auto count = vectCipher.size();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    auto vectU = getVectC1(vectCipher);
    auto vectV = getVectC2(vectCipher);


    vector<biginteger> rForRVect;
    vector<shared_ptr<GroupElement>> msgUVect, msgVVect;

    for(size_t i = 0 ; i < count ; i++){
        rForRVect.push_back(getRandomInRange(1, q - 1, random.get())); 
        msgUVect.push_back(dlog->exponentiate(vectU.at(i).get(), rForRVect.at(i)));
        msgVVect.push_back(dlog->exponentiate(vectV.at(i).get(), rForRVect.at(i)));             
    }

    sendVectGpElt(prover, msgUVect);
    sendVectGpElt(prover, msgVVect);

    // Challenge = Hash( h, msgU, msgV )
    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(h);
    vectGpElt.insert(vectGpElt.end(), msgUVect.begin(), msgUVect.end());
    vectGpElt.insert(vectGpElt.end(), msgVVect.begin(), msgVVect.end());
    
    auto challenge = generateChallenge(vectGpElt, q);

    vector<biginteger> msgZVect;
    for(int i = 0 ; i<count ; i++){
        msgZVect.push_back((rForRVect.at(i) + challenge * rBlindVect.at(i)) % q);
    }

    sendVectBigint(prover, msgZVect);

    auto str = receiveStr(prover);
    cout << "END niZKMultiANDBlindedProver ..." << endl;
    return ((str == "Success") ? 1 : 0);
}

int niZKMultiANDPartialDecProver(shared_ptr<CommParty> prover, shared_ptr<OpenSSLDlogECFp> dlog, 
shared_ptr<PublicKey> provThreshPubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, 
biginteger provPrivKey){
    cout << "Run niZKMultiANDPartialDecProver ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();
    auto count = vectCipher.size();

    auto vectU = getVectC1(vectCipher);
    auto provPK = dynamic_cast<ElGamalPublicKey*>(provThreshPubKey.get())->getH();

    vector<biginteger> rForRVect; 
    vector<shared_ptr<GroupElement>> msgUVect, msgVVect;

    for (size_t i = 0; i < count; i++)
    {
        rForRVect.push_back(getRandomInRange(1, dlog->getOrder() - 1, random.get()));
        msgUVect.push_back(dlog->exponentiate(g.get(), rForRVect.at(i)));
        msgVVect.push_back(dlog->exponentiate(vectU.at(i).get(), rForRVect.at(i))); 
    }

    sendVectGpElt(prover, msgUVect);
    sendVectGpElt(prover, msgVVect);

    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(provPK);
    vectGpElt.insert(vectGpElt.end(), msgUVect.begin(), msgUVect.end());
    vectGpElt.insert(vectGpElt.end(), msgVVect.begin(), msgVVect.end());
    
    auto challenge = generateChallenge(vectGpElt, q);

    vector<biginteger> msgZVect;

    for(int i = 0 ; i<count ; i++){
        msgZVect.push_back((rForRVect.at(i) + challenge * provPrivKey) % q);
    }

    sendVectBigint(prover, msgZVect);  

    auto str = receiveStr(prover);
    cout << "END niZKMultiANDPartialDecProver ..." << endl;
    return ((str == "Success") ? 1 : 0);
}











/* Verifier */

/* [Verifier] Simple */
bool niZKDecZeroVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher){
    cout << "Run niZKDecZeroVerifier ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    auto u = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC1();
    auto v = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC2();

    auto msgU = receiveGpElt(verifier, dlog);     
    auto msgV = receiveGpElt(verifier, dlog);  
    auto msgZ = receiveBigint(verifier);

    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(h);
    vectGpElt.push_back(msgU);
    vectGpElt.push_back(msgV);

    auto challenge = generateChallenge(vectGpElt, q);

    auto verify1Part1 = dlog->exponentiate(g.get(), msgZ);
    auto hPowChallenge = dlog->exponentiate(h.get(), challenge);
    auto verify1Part2 = dlog->multiplyGroupElements(msgU.get(), hPowChallenge.get());

    auto verify2Part1 = dlog->exponentiate(u.get(), msgZ);
    auto vPowChallenge = dlog->exponentiate(v.get(), challenge);
    auto verify2Part2 = dlog->multiplyGroupElements(msgV.get(), vPowChallenge.get());

    bool verify1 = areEqual(verify1Part1, verify1Part2);
    bool verify2 = areEqual(verify2Part1, verify2Part2);
    bool result = (verify1 && verify2);

    (result ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));

    cout << "END niZKDecZeroVerifier ..." << endl;
    return result;
}

bool niZKBlindedVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, shared_ptr<AsymmetricCiphertext> cipher, shared_ptr<AsymmetricCiphertext> blindedCipher){
    cout << "Run niZKBlindedVerifier ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    auto u = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC1();
    auto v = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC2();

    auto a = dynamic_cast<ElGamalOnGroupElementCiphertext*>(blindedCipher.get())->getC1();
    auto b = dynamic_cast<ElGamalOnGroupElementCiphertext*>(blindedCipher.get())->getC2();

    /* THIS SHOULD BE HANDLED OUTSIDE THE CURRENT FUNCTION */
    /* if( a->isIdentity() || b->isIdentity()){
            cout << "Abort" << endl;
    } */

    auto msgU = receiveGpElt(verifier, dlog);     
    auto msgV = receiveGpElt(verifier, dlog); 
    auto msgZ = receiveBigint(verifier);

    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(h);
    vectGpElt.push_back(msgU);
    vectGpElt.push_back(msgV);
    
    auto challenge = generateChallenge(vectGpElt, q); 
    
    /* 
    *       Verify:
    *                   u^msgZ =? msgU * a^challenge
    *                   v^msgZ =? msgV * b^challenge
    *  
    */

    auto verify1Part1 = dlog->exponentiate(u.get(), msgZ);
    auto aPowChallenge = dlog->exponentiate(a.get(), challenge);
    auto verify1Part2 = dlog->multiplyGroupElements(msgU.get(), aPowChallenge.get());

    auto verify2Part1 = dlog->exponentiate(v.get(), msgZ);
    auto bPowChallenge = dlog->exponentiate(b.get(), challenge);
    auto verify2Part2 = dlog->multiplyGroupElements(msgV.get(), bPowChallenge.get());
    
    bool verify1 = areEqual(verify1Part1, verify1Part2);
    bool verify2 = areEqual(verify2Part1, verify2Part2);
    bool result = (verify1 && verify2);

    (result ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));

    cout << "END niZKBlindedVerifier ..." << endl;
    return result;
}

bool niZKPartialDecVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<PublicKey> provThreshPubKey, shared_ptr<AsymmetricCiphertext> cipher, shared_ptr<GroupElement> partialCipher){
    cout << "Run niZKPartialDecVerifier ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto provPK = dynamic_cast<ElGamalPublicKey*>(provThreshPubKey.get())->getH();

    auto u = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC1();
    auto v = dynamic_cast<ElGamalOnGroupElementCiphertext*>(cipher.get())->getC2();

    /* Receive */
    auto msgU = receiveGpElt(verifier, dlog);
    auto msgV = receiveGpElt(verifier, dlog);
    auto msgZ = receiveBigint(verifier);    

    /* Challenge */ 
    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(provPK);
    vectGpElt.push_back(msgU);
    vectGpElt.push_back(msgV);
    
    auto challenge = generateChallenge(vectGpElt, q);

    /* 
    *       Verify:
    *                 g^msgZ  ==?  msgU * (provPK)^challenge
    *                 u^msgZ  ==?  msgV * (v * partialCipher^{-1} )^challenge
    *  
    */ 

    auto verify1Part1 = dlog->exponentiate(g.get(), msgZ);
    auto provPKPowChallenge = dlog->exponentiate(provPK.get(), challenge);
    auto verify1Part2 = dlog->multiplyGroupElements(msgU.get(), provPKPowChallenge.get());

    auto verify2Part1 = dlog->exponentiate(u.get(), msgZ);
    auto invPartCipher = dlog->getInverse(partialCipher.get());
    auto vMultInvPartCipher = dlog->multiplyGroupElements(v.get(),invPartCipher.get());
    auto vInvPrtCiphPowChallenge = dlog->exponentiate(vMultInvPartCipher.get(), challenge);
    auto verify2Part2 = dlog->multiplyGroupElements(msgV.get(), vInvPrtCiphPowChallenge.get());
    
    bool verify1 = areEqual(verify1Part1, verify1Part2);
    bool verify2 = areEqual(verify2Part1, verify2Part2);
    bool result = (verify1 && verify2);

    (result ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));

    cout << "END niZKPartialDecVerifier ..." << endl;
    return result;
}



/* [Verifier] Multiple AND */

bool niZKMultiANDDecZeroVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
    cout << "Run niZKMultiANDDecZeroVerifier ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    auto vectU = getVectC1(vectCipher);
    auto vectV = getVectC2(vectCipher);
    
    auto msgUVect = receiveVectGpElt(verifier, dlog);     
    auto msgVVect = receiveVectGpElt(verifier, dlog);  

    auto msgZVect = receiveVectBigint(verifier); 

    // Challenge = Hash( h, msgU, msgV )
    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(h);
    vectGpElt.insert(vectGpElt.end(), msgUVect.begin(), msgUVect.end());
    vectGpElt.insert(vectGpElt.end(), msgVVect.begin(), msgVVect.end());
    
    auto challenge = generateChallenge(vectGpElt, q);
    
    shared_ptr<GroupElement> msgU, msgV, u, v;
    biginteger msgZ;
    bool result = true;

    BOOST_FOREACH(boost::tie(msgZ, msgU, msgV, u, v), boost::combine(msgZVect, msgUVect, msgVVect, vectU, vectV)){
        auto verify1Part1 = dlog->exponentiate(g.get(), msgZ);
        auto hPowChallenge = dlog->exponentiate(h.get(), challenge);
        auto verify1Part2 = dlog->multiplyGroupElements(msgU.get(), hPowChallenge.get());

        auto verify2Part1 = dlog->exponentiate(u.get(), msgZ);
        auto vPowChallenge = dlog->exponentiate(v.get(), challenge);
        auto verify2Part2 = dlog->multiplyGroupElements(msgV.get(), vPowChallenge.get());

        bool verify1 = areEqual(verify1Part1, verify1Part2);
        bool verify2 = areEqual(verify2Part1, verify2Part2);
        result = result && (verify1 && verify2);
    
    }

    (result ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));
    cout << "END niZKMultiANDDecZeroVerifier ..." << endl;
    return result;
}

bool niZKMultiANDBlindedVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, shared_ptr<ElGamalOnGroupElementEnc> elgamal,
 vector<shared_ptr<AsymmetricCiphertext>> vectCipher, vector<shared_ptr<AsymmetricCiphertext>> vectBlindedCipher){
    cout << "Run niZKMultiANDBlindedVerifier ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto h = dynamic_cast<ElGamalPublicKey*>(elgamal->getPublicKey().get())->getH();

    auto vectU = getVectC1(vectCipher);
    auto vectV = getVectC2(vectCipher);
    auto vectA = getVectC1(vectBlindedCipher);
    auto vectB = getVectC2(vectBlindedCipher);

    auto msgUVect = receiveVectGpElt(verifier, dlog);     
    auto msgVVect = receiveVectGpElt(verifier, dlog); 
    auto msgZVect = receiveVectBigint(verifier);

    // Challenge = Hash( h, msgU, msgV )
    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(h);
    vectGpElt.insert(vectGpElt.end(), msgUVect.begin(), msgUVect.end());
    vectGpElt.insert(vectGpElt.end(), msgVVect.begin(), msgVVect.end());
    
    auto challenge = generateChallenge(vectGpElt, q);

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
    cout << "END niZKMultiANDBlindedVerifier ..." << endl;
    return result;
}

bool niZKMultiANDPartialDecVerifier(shared_ptr<CommParty> verifier, shared_ptr<OpenSSLDlogECFp> dlog, 
shared_ptr<PublicKey> provThreshPubKey, vector<shared_ptr<AsymmetricCiphertext>> vectCipher, 
vector<shared_ptr<GroupElement>> partialCipherVect){
    cout << "Run niZKMultiANDPartialDecVerifier ..." << endl;
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();
    auto random = get_seeded_prg();

    auto provPK = dynamic_cast<ElGamalPublicKey*>(provThreshPubKey.get())->getH();

    auto vectU = getVectC1(vectCipher);
    auto vectV = getVectC2(vectCipher);

    
    auto msgUVect = receiveVectGpElt(verifier, dlog);
    auto msgVVect = receiveVectGpElt(verifier, dlog);
    auto msgZVect = receiveVectBigint(verifier);

    // Challenge = Hash( jointPK, msgU, msgV )
    vector<shared_ptr<GroupElement>> vectGpElt;

    vectGpElt.push_back(provPK);
    vectGpElt.insert(vectGpElt.end(), msgUVect.begin(), msgUVect.end());
    vectGpElt.insert(vectGpElt.end(), msgVVect.begin(), msgVVect.end());
    
    auto challenge = generateChallenge(vectGpElt, q);

    biginteger msgZ;
    shared_ptr<GroupElement> msgU, msgV, u, v, partialCipher;
    bool result = true;

    BOOST_FOREACH(boost::tie(msgZ, msgU, msgV, u, v, partialCipher), boost::combine(msgZVect, msgUVect, msgVVect, vectU, vectV, partialCipherVect)){

        auto verify1Part1 = dlog->exponentiate(g.get(), msgZ);
        auto provPKPowChallenge = dlog->exponentiate(provPK.get(), challenge);
        auto verify1Part2 = dlog->multiplyGroupElements(msgU.get(), provPKPowChallenge.get());

        auto verify2Part1 = dlog->exponentiate(u.get(), msgZ);
        auto invPartCipher = dlog->getInverse(partialCipher.get());
        auto vMultInvPartCipher = dlog->multiplyGroupElements(v.get(),invPartCipher.get());
        auto vInvPrtCiphPowChallenge = dlog->exponentiate(vMultInvPartCipher.get(), challenge);
        auto verify2Part2 = dlog->multiplyGroupElements(msgV.get(), vInvPrtCiphPowChallenge.get());

        bool verify1 = areEqual(verify1Part1, verify1Part2);
        bool verify2 = areEqual(verify2Part1, verify2Part2);
        result = result && (verify1 && verify2);

    }
    (result ? verifier->writeWithSize("Success") : verifier->writeWithSize("Failure"));
    cout << "END niZKMultiANDPartialDecVerifier ..." << endl;
    return result;
}






