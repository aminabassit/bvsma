#include <boost/filesystem.hpp>


#include "bvsma/include/functions.hpp"
#include "bvsma/include/ZKProofs.hpp"
#include "bvsma/include/SchnorrSignature.hpp"
#include "bvsma/include/fileFunctions.hpp"
#include "bvsma/include/functionsParallel.hpp"


using namespace boost::filesystem;


using namespace std;
typedef unsigned char byte;


/* Gen exp */

//  ./client 0 192 501 1 /home/obre/bvsma/data/BMDB.csv BMDB 36 16
//  ./client 0 224 501 1 /home/obre/bvsma/data/BMDB.csv BMDB 36 16
//  ./client 0 256 501 1 /home/obre/bvsma/data/BMDB.csv BMDB 36 16


//  ./client 0 192 501 1 /home/obre/bvsma/data/PUT.csv PUT 49 64
//  ./client 0 224 501 1 /home/obre/bvsma/data/PUT.csv PUT 49 64
//  ./client 0 256 501 1 /home/obre/bvsma/data/PUT.csv PUT 49 64

//  ./client 0 192 501 1 /home/obre/bvsma/data/FRGC.csv FRGC 94 64
//  ./client 0 224 501 1 /home/obre/bvsma/data/FRGC.csv FRGC 94 64
//  ./client 0 256 501 1 /home/obre/bvsma/data/FRGC.csv FRGC 94 64

/* Imp exp */



int main(int argc, char* argv[]){
    cout << "Run Malicious Client ..." << endl;

    boost::asio::io_service io_service;

    auto clientIp = IpAddress::from_string("127.0.0.1");
    auto serverIp = IpAddress::from_string("127.0.0.1");
    auto enrollServerIp = IpAddress::from_string("127.0.0.1");
    
    SocketPartyData clientParty(clientIp, 1222);
    SocketPartyData clientParty2(clientIp, 8002);

    SocketPartyData serverParty(serverIp, 1223);
    SocketPartyData enrollServerParty(enrollServerIp, 1224); 

    shared_ptr<CommParty> withEnrollServer, client;

    if (stoi(argv[1]) == 0){
        withEnrollServer = make_shared<CommPartyTCPSynced>(io_service, clientParty2, enrollServerParty); 
    }
    else if(stoi(argv[1]) == 1){
        client = make_shared<CommPartyTCPSynced>(io_service, clientParty, serverParty);	
    }

    boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

    
    
    string dirClient = "../../../data/client/"+ string(argv[6]) +"/P"+ string(argv[2]);
    string enrLogTimer = dirClient +"/MALenrClientLogTimer.csv";
    string verLogTimer = dirClient +"/MALverClientLogTimer.csv";
    string resultMatch = dirClient +"/MALresultMatch.csv";
    string keyStorage;
    string dirUser;
    
    
    

    


    
    
    string qBinsFile = "../../../data/lookupTables/"+ string(argv[6]) +"/"+ string(argv[6]) +"_qbins.csv";
    string sensorFile = string(argv[5]);
    string dirLLR = "../../../data/lookupTables/"+ string(argv[6]) +"/";

    vector<int> maxNFQ(stoi(argv[7]), stoi(argv[8]));


    string configFile = "../../../../libscapi/include/configFiles/NISTEC.txt";
    string curve = "P-"+string(argv[2]);


	auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();

    shared_ptr<ElGamalOnGroupElementEnc> elgamalTH = make_shared<ElGamalOnGroupElementEnc>(dlog);
    shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);



    
    unsigned int seedClt = 149423;

    int resultInt;
    bool resultBool;

    string str;

    
    std::chrono::time_point<std::chrono::system_clock> globalStart;
    std::chrono::time_point<std::chrono::system_clock> localStart;
    std::chrono::time_point<std::chrono::system_clock> proofStart;

    std::ofstream out_file;



    
    try
    {
        
        if (stoi(argv[1]) == 0)
        {    
            int count = stoi(argv[3]);
            int step = stoi(argv[4]);

            withEnrollServer->join(500, 5000);             

            for (size_t i = 1; i < count; i=i+step)
            {   
                out_file.open(enrLogTimer, ios::app);
                if (!out_file)
                {
                    throw "Error creating file"s;
                }
                cout << "======= Enrollment =======" << endl;
                localStart = std::chrono::system_clock::now();
                globalStart = localStart;  

                auto pairSample = readSampleWithIDInLineFPD(sensorFile,  i  );
                auto userId = biginteger(pairSample.first);
                auto sample = pairSample.second;
                dirUser = dirClient +"/MAL/USERS/user"+userId.str();             
                                
                path pathUser(dirUser);
                create_directory(pathUser);
                dirUser = dirUser+"/";

                keyStorage = dirUser+"keystorage.txt";

                auto pair = elgamal->generateKey();
                elgamal->setKey(pair.first, pair.second);  
                auto x = dynamic_cast<ElGamalPrivateKey*>(pair.second.get())->getX();
                writeBigintinFile(keyStorage, "client", "PrivKS", x);          
                writePubKeyinFile(keyStorage, "client", "PubKS", pair.first);             
                cout << "-> Client PrivKS and PubKS Generated and Stored  ..." << endl;

                sendBigint(withEnrollServer, userId);
                cout << "-> User " << userId << " Enrollment Request ..." << endl; 

                sendElGamalPubKey(withEnrollServer, pair.first);
                cout << "-> Client PubKS Sent ..." << endl;         
                
                auto pairTH = elgamalTH->generateKey();            
                auto s1 = dynamic_cast<ElGamalPrivateKey*>(pairTH.second.get())->getX();
                writeBigintinFile(keyStorage, "client", "PrivTH", s1);
                
                auto clientPKeyTH = pairTH.first;
                writePubKeyinFile(keyStorage, "client", "PubTH", clientPKeyTH);
                cout << "-> Client PrivTH and PubTH Generated and Stored ..." << endl;             
                
                sendElGamalPubKey(withEnrollServer, clientPKeyTH);
                cout << "-> Client PubTH Sent ..." << endl;

                auto verKey = receiveGpElt(withEnrollServer, dlog);
                writeGPELTinFile(keyStorage, "enrollServer", "VerKey", verKey);
                cout << "-> EnrollmentServer VerKey Received and stored ..." << endl;
                
                auto serverPKeyTH = receiveElGamalPubKey(withEnrollServer, dlog, elgamalTH);  
                writePubKeyinFile(keyStorage, "server", "PubTH", serverPKeyTH); 
                cout << "-> Server PubTH Received and Stored ..." << endl; 

                auto jointPubKey = receiveElGamalPubKey(withEnrollServer, dlog, elgamalTH);
                elgamalTH->setKey(jointPubKey, pairTH.second);
                writePubKeyinFile(keyStorage, "joint", "jointTH", jointPubKey); 
                writeCSVNew(out_file, localStart, false);
                cout << "-> Joint jointTH Received and stored ..." << endl;         
                cout << "----> Keys Establishment DONE ..." << endl;            


                cout << "-------------------------------------------" << endl;


                localStart = std::chrono::system_clock::now();
                auto thresholdEncSet = receiveVectElGamalCipher(withEnrollServer, dlog, elgamalTH);   
                writeVectCipherinFile(dirUser+"thresholdEncSet.txt", thresholdEncSet);  
                writeCSVNew(out_file, localStart, false);   
                cout << "----> Threshold Set Encrypted and Permuted Received and Stored ..." << endl;            


                cout << "-------------------------------------------" << endl;


                localStart = std::chrono::system_clock::now();

                auto colEncMap = encryptColIndices(dlog, elgamal, maxNFQ);  
                auto quantizedSample = quantizefeaturesFPD(qBinsFile, sample);
                auto scoreEncMap = encryptRowsFromHELR(dirLLR, dlog, elgamalTH, quantizedSample);
                
                vector<int> vectBegin(maxNFQ.size(),0);        
                map<int, vector<int>> permutation = generateMapIntPermutation(seedClt, maxNFQ.size(), vectBegin, maxNFQ);
                writePermutation(dirUser+"permutation.txt", permutation);
                cout << "-> Permutation Generated and Stored ..." << endl;

                auto partialTemplate = generatePartialTemplate(userId, permutation, colEncMap, scoreEncMap);            
                sendMapOfVectComponent(withEnrollServer, partialTemplate);
                writeCSVNew(out_file, localStart, false);   
                writeCSVNew(out_file, globalStart, true);
                cout << "-> Partial Template Generated and Sent ..." << endl;
                cout << "======= Enrollment END =======" << endl;

            }
            
            
            




        }
        else if(stoi(argv[1]) == 1){

            int count = stoi(argv[3]);
            int step = stoi(argv[4]);
            
            client->join(500, 5000);             

            for (size_t i = 2; i < count; i=i+step)
            {   
                out_file.open(verLogTimer, ios::app);
                if (!out_file)
                {
                    throw "Error creating file"s;
                }
                cout << "======= Verification =======" << endl;
                localStart = std::chrono::system_clock::now();
                globalStart = localStart; 

                // cout << "--> Step 1: User's existence verification ..." << endl; 

                auto pairSample = readSampleWithIDInLineFPD(sensorFile, i);
                auto userId = biginteger(pairSample.first); 
                userId -= 1;
                sendBigint(client, userId);
                str = receiveStr(client);
                if( "Unregistered" == str){
                    throw "Unregistered User"s; 
                }                 
                cout << "User " << userId << " is " << str << endl;
                writeCSVNew(out_file, localStart, false);

                // load
                localStart = std::chrono::system_clock::now();
                
                dirUser = dirClient +"/MAL/USERS/user"+userId.str()+"/";
                keyStorage = dirUser+"keystorage.txt"; 

                auto s1 = readBigintFromfile(keyStorage, "client", "PrivTH");
                ElGamalPrivateKey cltPrivKeyTH(s1);
                shared_ptr<PrivateKey> clientPrivKeyTH = make_shared<ElGamalPrivateKey>(cltPrivKeyTH);
                auto serverPKeyTH = readPubKeyFromfile(keyStorage, dlog, "server", "PubTH");              
                auto jointPubKey = readPubKeyFromfile(keyStorage, dlog, "joint", "jointTH"); 
                elgamalTH->setKey(jointPubKey, clientPrivKeyTH); 

                SchnorrSignature schnorr(dlog);
                auto verKey = readGPEltFromfile(keyStorage, dlog, "enrollServer", "VerKey");
                schnorr.setVerifKey(verKey);

                auto x = readBigintFromfile(keyStorage, "client", "PrivKS");
                ElGamalPrivateKey cltPrivKey(x);
                shared_ptr<PrivateKey> clientPrivKey = make_shared<ElGamalPrivateKey>(cltPrivKey);
                auto clientPKey = readPubKeyFromfile(keyStorage, dlog, "client", "PubKS");
                elgamal->setKey(clientPKey, clientPrivKey);   

                auto thresholdEncSet = readVectCipherFromFile(dirUser+"thresholdEncSet.txt", dlog);

                writeCSVNew(out_file, localStart, false);
                cout << "----> Keys and Threshold Set loaded ..." << endl;
                cout << "--> Step 1: DONE ..." << endl;
                cout << endl;          


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 2: Probe verification ..." << endl;
                localStart = std::chrono::system_clock::now();

                auto sample = pairSample.second;
                vector<int> rawProbe = quantizefeaturesFPD(qBinsFile, sample);           
                vector<biginteger> quantizedProbe(rawProbe.begin(), rawProbe.end());
                auto vectRforProbe = generateVectBigintRand_parallel( q, quantizedProbe.size());  
                // auto vectRforProbe = generateVectBigintRand( q, quantizedProbe.size());

                auto probeEnc = generateVectElGamalCiphersFromVects_parallel(configFile, curve, clientPKey, quantizedProbe, vectRforProbe);
                // auto probeEnc = generateVectElGamalCiphersFromVects(dlog, elgamal, quantizedProbe, vectRforProbe);
                sendVectElGamalCipher(client, probeEnc);
                auto indexCompVect = readSpecificPermutation(dirUser+"permutation.txt", rawProbe);
                sendIntVect(client, indexCompVect);

                proofStart = std::chrono::system_clock::now();
                resultInt = zkPoKMultiANDPlainProver_parallel(client, configFile, curve, clientPKey, quantizedProbe, vectRforProbe);
                if( resultInt == 0){ 
                    client->writeWithSize("Incorrect Commitment");
                    throw "Incorrect Commitment"s;
                }
                client->writeWithSize("Correct Commitment");           

                str = receiveStr(client);
                if( "Proof Failure" == str){
                    throw "Proof Failure"s; 
                }          
                cout << str << endl;
                writeCSVNew(out_file, proofStart, false);

                writeCSVNew(out_file, localStart, false);
                cout << "--> Step 2: DONE ..." << endl;
                cout << endl;


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 3: Protected individual scores exchange ..." << endl;
                localStart = std::chrono::system_clock::now();

                auto requestedComp = receiveVectComponent(client, dlog, elgamal, elgamalTH);
                auto colEncFromTemp = extractColEncFromTemp_parallel(requestedComp);
                auto scoreEncFromTemp = extractScoreEncFromTemp_parallel(requestedComp);  
                // auto colEncFromTemp = extractColEncFromTemp(requestedComp);
                // auto scoreEncFromTemp = extractScoreEncFromTemp(requestedComp);  

                proofStart = std::chrono::system_clock::now();            
                auto verSigResult = verifyVectCompSignatures_parallel(configFile, curve, verKey, requestedComp);   
                if( verSigResult == false){
                    client->writeWithSize("Incorrect Signature");
                    throw "Incorrect Signature"s;
                }
                client->writeWithSize("Correct Signature");
                cout << "Correct Signature" << endl;
                writeCSVNew(out_file, proofStart, false);

                auto cipherDecZeroVect = subtractTwoCipherVect_parallel(configFile, curve, clientPKey, colEncFromTemp, probeEnc);   
                // auto cipherDecZeroVect = subtractTwoCipherVect(dlog, elgamal, colEncFromTemp, probeEnc);   

                proofStart = std::chrono::system_clock::now(); 
                resultInt = niZKMultiANDDecZeroProver_parallel(client, configFile, curve, clientPKey, cipherDecZeroVect, x);
                if( resultInt == 0){
                    throw "Proof Failure"s;
                }
                cout << "Successful Proof" << endl;
                writeCSVNew(out_file, proofStart, false);

                writeCSVNew(out_file, localStart, false);
                cout << "--> Step 3: DONE ..." << endl;
                cout << endl;


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 4: Comparison of the similarity score with the threshold set ..." << endl;
                localStart = std::chrono::system_clock::now();

                // auto finalScore = multiplyCiphersOfVect_parallel(configFile, curve, jointPubKey, scoreEncFromTemp);                
                auto finalScore = multiplyCiphersOfVect(elgamalTH, scoreEncFromTemp);

                auto comparisonVect = subtractOneCipherFromCipherVect_parallel(configFile, curve, jointPubKey, thresholdEncSet, finalScore);
                // auto comparisonVect = subtractOneCipherFromCipherVect(dlog, elgamalTH, thresholdEncSet, finalScore);

                auto comparisonVectBlinded = receiveVectElGamalCipher(client, dlog, elgamalTH);
                auto partialDecBlindedCompVect = receiveVectGpElt(client, dlog);

                proofStart = std::chrono::system_clock::now();
                // resultBool = niZKMultiANDBlindedVerifier_parallel(client, configFile, curve, jointPubKey, comparisonVect, comparisonVectBlinded);
                resultBool = niZKMultiANDBlindedVerifier(client, dlog, elgamalTH, comparisonVect, comparisonVectBlinded);
                if(resultBool == false){
                    throw "Proof Failure"s;
                }
                cout << "Successful Proof" << endl;
                writeCSVNew(out_file, proofStart, false);

                proofStart = std::chrono::system_clock::now();
                // resultBool = niZKMultiANDPartialDecVerifier_parallel(client, configFile, curve, serverPKeyTH, comparisonVectBlinded, partialDecBlindedCompVect);
                resultBool = niZKMultiANDPartialDecVerifier(client, dlog, serverPKeyTH, comparisonVectBlinded, partialDecBlindedCompVect);
                if(resultBool == false){
                    throw "Proof Failure"s;
                }
                cout << "Successful Proof" << endl;
                writeCSVNew(out_file, proofStart, false);

                writeCSVNew(out_file, localStart, false);
                cout << "--> Step 4: DONE ..." << endl;
                cout << endl;


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 5: Verification of the similarity score with the threshold ..." << endl;
                localStart = std::chrono::system_clock::now();

                resultBool = finalDecryptionANDMatch(elgamalTH, comparisonVectBlinded, partialDecBlindedCompVect);
                if( resultBool == false){
                    client->writeWithSize("No Match");
                    writeResult(resultMatch, 0);
                    cout << "No Match" << endl;            
                }else{
                    client->writeWithSize("Match");
                    writeResult(resultMatch, 1);
                    cout << "Match" << endl;
                }
                writeCSVNew(out_file, localStart, false);
                writeCSVNew(out_file, globalStart, true);
                cout << "--> Step 5: DONE ..." << endl;
                cout << endl;
                cout << "======= Verification END =======" << endl;

            }

            

        }
        


    }
    catch (const logic_error& e) {
        out_file.close();
        io_service.stop();
        t.join(); 
		cerr << e.what();        
	} 
    catch (string &e){
        out_file.close();
        io_service.stop();
        t.join(); 
        cerr << e << endl; 
    }
    
    io_service.stop();
    t.join(); 

    cout << "END Malicious Client ..." << endl;
    return 0;

}