
#include "bvsma/include/ZKProofs.hpp"
#include "bvsma/include/functionsParallel.hpp"

#include <chrono>

using namespace std;
typedef unsigned char byte;


// ./proverParallel 192 zkPoKMultiANDPlain
// ./proverParallel 224 zkPoKMultiANDPlain
// ./proverParallel 256 zkPoKMultiANDPlain



int main(int argc, char* argv[]){
    cout << "Run Main Prover ..." << endl;

    boost::asio::io_service io_service;
    auto proverIp = IpAddress::from_string("127.0.0.1");
	auto verifierIp = IpAddress::from_string("127.0.0.1"); 
	SocketPartyData proverParty(proverIp, 1222);
	SocketPartyData verifierParty(verifierIp, 1223);  
    shared_ptr<CommParty> prover = make_shared<CommPartyTCPSynced>(io_service, proverParty, verifierParty); 
    boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

    string configFile = "../../../libscapi/include/configFiles/NISTEC.txt";
    string curve = "P-"+string(argv[1]);
    

	auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();

    biginteger w(100);    
    auto h = dlog->exponentiate(g.get(), w);


    /**************/

    // Normal ElGamal Prover's keyPair (fixed only for the test) 
    shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);
    // Prover's keyPair    
    biginteger x(42);
    ElGamalPrivateKey privProv(x);
    shared_ptr<PrivateKey> proverPrivKey = make_shared<ElGamalPrivateKey>(privProv);

    ElGamalPublicKey pubProv(dlog->exponentiate(g.get(), x));
    shared_ptr<PublicKey> proverPubKey = make_shared<ElGamalPublicKey>(pubProv);

    elgamal->setKey(proverPubKey, proverPrivKey);
    
    
    /**************/


    // Threshold ElGamal keys (fixed only for the test)
    shared_ptr<ElGamalOnGroupElementEnc> elgamalThresholdProv = make_shared<ElGamalOnGroupElementEnc>(dlog);
    shared_ptr<ElGamalOnGroupElementEnc> elgamalThresholdVerif = make_shared<ElGamalOnGroupElementEnc>(dlog);

    // thresholdKeyPair
    biginteger x1(50), x2(60);
    /* Prover */
    ElGamalPrivateKey privProvThreshold(x1);
    shared_ptr<PrivateKey> proverPrivKeyThreshold = make_shared<ElGamalPrivateKey>(privProvThreshold);
    auto pubProvThreshold = dlog->exponentiate(g.get(), x1);
    shared_ptr<PublicKey> proverPubKeyThreshold = make_shared<ElGamalPublicKey>(pubProvThreshold);
    /* Verifier */
    ElGamalPrivateKey privVerifThreshold(x2);
    shared_ptr<PrivateKey> verifierPrivKeyThreshold = make_shared<ElGamalPrivateKey>(privVerifThreshold);
    auto pubVerifThreshold = dlog->exponentiate(g.get(), x2);
    /* Joint */
    auto jointH = dlog->multiplyGroupElements(pubVerifThreshold.get(),pubProvThreshold.get());    
    ElGamalPublicKey jointPK(jointH);
    shared_ptr<PublicKey> jointPubKey = make_shared<ElGamalPublicKey>(jointPK); 

    elgamalThresholdProv->setKey(jointPubKey, proverPrivKeyThreshold); 
    elgamalThresholdVerif->setKey(jointPubKey, verifierPrivKeyThreshold); 

   

    /**************/

    biginteger m(100), r(40);    
    auto gPowM = dlog->exponentiate(g.get(), m);    
    auto cipher = elgamal->encrypt(make_shared<GroupElementPlaintext>(gPowM), r);

    /**************/

    biginteger r1(66), r2(76), zero(0);    
    auto gPowMDec = dlog->exponentiate(g.get(), m);    
    auto cipher1 = elgamal->encrypt(make_shared<GroupElementPlaintext>(gPowMDec), r1);
    auto cipher2 = elgamal->encrypt(make_shared<GroupElementPlaintext>(gPowMDec), r2);
    auto invCipher2 = inverseCipherElGamal(dlog, cipher2);
    auto cipherDecZero = elgamal->multiply(cipher1.get(), invCipher2.get(), zero);

    /**************/

    biginteger rBlind(35);
    auto blindedCipher = blindCipherElGamal(dlog, cipher, rBlind);

    /**************/

    auto cipherForPartial =  elgamalThresholdProv->encrypt(make_shared<GroupElementPlaintext>(gPowM), r);
    auto partCipher = elgamalThresholdProv->decrypt(cipherForPartial.get());
    auto partialCipher = dynamic_cast<GroupElementPlaintext*>(partCipher.get())->getElement();

    /**************/

    auto vectM = generateVectBigintFixed(q, 55, 384);
    auto vectR = generateVectBigintFixed(q, 61, 384);
    auto vectCipher = generateVectElGamalCiphersFromVects(dlog, elgamal, vectM, vectR);

    /**************/    

    auto vectR1 = generateVectBigintFixed(q, 20, 384);
    auto vectR2 = generateVectBigintFixed(q, 15, 384);
    auto vectCipher1 = generateVectElGamalCiphersFromVects(dlog, elgamal, vectM, vectR1);
    auto vectCipher2 = generateVectElGamalCiphersFromVects(dlog, elgamal, vectM, vectR2);
    auto cipherDecZeroVect = subtractTwoCipherVect(dlog, elgamal, vectCipher1, vectCipher2);
    
    /**************/
    
    auto vectM3 = generateVectBigintFixed(q, 55, 100);
    auto vectR3 = generateVectBigintFixed(q, 61, 100);
    auto vectCipher3 = generateVectElGamalCiphersFromVects(dlog, elgamal, vectM3, vectR3);

    auto vectRBlind = generateVectBigintFixed(q, 31, 100);
    auto vectBlindedCipher = blindVectCipherElGamal(dlog, vectCipher3, vectRBlind);

    
    /**************/

    auto vectCipherForPartial = generateVectElGamalCiphersFromVects(dlog, elgamalThresholdProv, vectM3, vectR3);
    auto vectPartialCipher = partiallyDecryptVectCiphers(elgamalThresholdProv, vectCipherForPartial);

    string zkProof = argv[2];
    std::chrono::time_point<std::chrono::system_clock> start;

    try
    {
        prover->join(500, 5000);         

        if ( zkProof == "zkPoKBasic"){
            start = std::chrono::system_clock::now();
            auto result = zkPoKBasicProver(prover, dlog, h, w);
            print_elapsed_ms(start, zkProof);
            cout << "Prover is done with " << (result ? "Success" : "Failure") << endl;
        } 
        else if ( zkProof == "zkPoKSinglePlain") {
            start = std::chrono::system_clock::now();
            auto result = zkPoKSinglePlainProver(prover, dlog, elgamal, m, r);
            print_elapsed_ms(start, zkProof);
            cout << "Prover is done with " << (result ? "Success" : "Failure") << endl;
        }
        else if(zkProof == "niZKDecZero"){
            start = std::chrono::system_clock::now();
            auto result = niZKDecZeroProver(prover, dlog, elgamal, cipherDecZero, x);
            print_elapsed_ms(start, zkProof);
            cout << "Prover is done with " << (result ? "Success" : "Failure") << endl;
        }
        else if(zkProof == "niZKBlinded"){
            start = std::chrono::system_clock::now();
            auto result = niZKBlindedProver(prover, dlog, elgamal, cipher, rBlind);
            print_elapsed_ms(start, zkProof);
            cout << "Prover is done with " << (result ? "Success" : "Failure") << endl;
        }
        else if(zkProof == "niZKPartialDec"){
            start = std::chrono::system_clock::now();
            auto result = niZKPartialDecProver(prover, dlog, proverPubKeyThreshold, cipherForPartial, x1);
            print_elapsed_ms(start, zkProof);
            cout << "Prover is done with " << (result ? "Success" : "Failure") << endl;
        }
        else if(zkProof == "zkPoKMultiANDPlain"){
            start = std::chrono::system_clock::now();
            auto result1 = zkPoKMultiANDPlainProver_parallel(prover, configFile, curve, proverPubKey, vectM, vectR);
            print_elapsed_ms(start, zkProof);
            cout << "Parallel Prover is done with " << (result1 ? "Success" : "Failure") << endl;

            start = std::chrono::system_clock::now();
            auto result = zkPoKMultiANDPlainProver(prover, dlog, elgamal, vectM, vectR);
            print_elapsed_ms(start, zkProof);
            cout << "Prover is done with " << (result ? "Success" : "Failure") << endl;

        }
        else if(zkProof == "niZKMultiANDDecZero"){

            start = std::chrono::system_clock::now();
            auto result1 = niZKMultiANDDecZeroProver_parallel(prover, configFile, curve, proverPubKey,  cipherDecZeroVect, x);
            print_elapsed_ms(start, zkProof);
            cout << "Parallel Prover is done with " << (result1 ? "Success" : "Failure") << endl;


            start = std::chrono::system_clock::now();
            auto result = niZKMultiANDDecZeroProver(prover, dlog, elgamal, cipherDecZeroVect, x);
            print_elapsed_ms(start, zkProof);
            cout << "Prover is done with " << (result ? "Success" : "Failure") << endl;
        }
        else if(zkProof == "niZKMultiANDBlinded"){

            start = std::chrono::system_clock::now();
            auto result1 = niZKMultiANDBlindedProver_parallel(prover, configFile, curve, proverPubKey, vectCipher3, vectRBlind);
            print_elapsed_ms(start, zkProof);
            cout << "Parallel Prover is done with " << (result1 ? "Success" : "Failure") << endl;


            start = std::chrono::system_clock::now();
            auto result = niZKMultiANDBlindedProver(prover, dlog, elgamal, vectCipher3, vectRBlind);
            print_elapsed_ms(start, zkProof);
            cout << "Prover is done with " << (result ? "Success" : "Failure") << endl;
        }
        else if(zkProof == "niZKMultiANDPartialDec"){

            start = std::chrono::system_clock::now();
            auto result1 = niZKMultiANDPartialDecProver_parallel(prover, configFile, curve, proverPubKeyThreshold, vectCipherForPartial, x1);
            print_elapsed_ms(start, zkProof);
            cout << "Parallel Prover is done with " << (result1 ? "Success" : "Failure") << endl;

            start = std::chrono::system_clock::now();
            auto result = niZKMultiANDPartialDecProver(prover, dlog, proverPubKeyThreshold, vectCipherForPartial, x1);
            print_elapsed_ms(start, zkProof);
            cout << "Prover is done with " << (result ? "Success" : "Failure") << endl;
        }
        else 
        {
            ProverUsage();
			return 1;
        }    

    }
    catch (const logic_error& e) {
        io_service.stop();
	    t.join(); 
		cerr << e.what();        
	} 
    
    io_service.stop();
	t.join(); 

    cout << "END Main Prover ..." << endl;
    return 0;

}