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

// ./server 0 192 501 1 BMDB
// ./server 0 224 501 1 BMDB
// ./server 0 256 501 1 BMDB

// ./server 0 192 501 1 PUT
// ./server 0 224 501 1 PUT
// ./server 0 256 501 1 PUT

// ./server 0 192 501 1 FRGC
// ./server 0 224 501 1 FRGC
// ./server 0 256 501 1 FRGC






int main(int argc, char* argv[]){
    cout << "Run Malicious Server ..." << endl;

    boost::asio::io_service io_service, io_service2;
    
    auto clientIp = IpAddress::from_string("127.0.0.1");
	auto serverIp = IpAddress::from_string("127.0.0.1");
    auto enrollServerIp = IpAddress::from_string("127.0.0.1");
    
    
    SocketPartyData clientParty(clientIp, 1222);    
    SocketPartyData enrollServerParty(enrollServerIp, 8004); 

    SocketPartyData serverParty(serverIp, 1223);
    SocketPartyData serverParty2(serverIp, 8003);

    shared_ptr<CommParty> withEnrollServer, server;

    if (stoi(argv[1]) == 0){
        withEnrollServer = make_shared<CommPartyTCPSynced>(io_service, serverParty2, enrollServerParty);
    }
    else if(stoi(argv[1]) == 1){
        server = make_shared<CommPartyTCPSynced>(io_service, serverParty, clientParty); 
    }


    boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));


    
    string dirServer = "../../../data/server/"+ string(argv[5]) +"/P"+ string(argv[2]);
    string enrLogTimer = dirServer +"/MALenrServerLogTimer.csv";
    string verLogTimer = dirServer +"/MALverServerLogTimer.csv";
    string keyStorage;
    string dirUser;
    
    


	string configFile = "../../../../libscapi/include/configFiles/NISTEC.txt";
    string curve = "P-"+string(argv[2]);


	auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();

    shared_ptr<ElGamalOnGroupElementEnc> elgamalTH = make_shared<ElGamalOnGroupElementEnc>(dlog);
    shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog); 

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
            
            
            withEnrollServer->join(500, 5000); 

            int count = stoi(argv[3]);
            int step = stoi(argv[4]);



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


                auto userId = receiveBigint(withEnrollServer);
                cout << "-> User " << userId << " Enrollment Request ..." << endl;
                dirUser = dirServer +"/MAL/USERS/user"+userId.str();
                path pathUser(dirUser);
                create_directory(pathUser);            
                dirUser = dirUser+"/";
                keyStorage = dirUser+"keystorage.txt";

                auto pairTH = elgamalTH->generateKey();            
                auto s2 = dynamic_cast<ElGamalPrivateKey*>(pairTH.second.get())->getX();
                writeBigintinFile(keyStorage, "server", "PrivTH", s2);
                
                auto serverPKeyTH = pairTH.first;
                writePubKeyinFile(keyStorage, "server", "PubTH", serverPKeyTH);
                cout << "-> Server PrivTH and PubTH Generated and Stored ..." << endl;             
                
                sendElGamalPubKey(withEnrollServer, serverPKeyTH);
                cout << "-> Server PubTH Sent ..." << endl;

                auto verKey = receiveGpElt(withEnrollServer, dlog);
                writeGPELTinFile(keyStorage, "enrollServer", "VerKey", verKey);
                cout << "-> EnrollmentServer VerKey Received and stored ..." << endl;
                
                auto clientPKeyTH = receiveElGamalPubKey(withEnrollServer, dlog, elgamalTH);  
                writePubKeyinFile(keyStorage, "client", "PubTH", clientPKeyTH); 
                cout << "-> Client PubTH Received and Stored ..." << endl; 

                auto cltPk = receiveElGamalPubKey(withEnrollServer, dlog, elgamalTH);  
                writePubKeyinFile(keyStorage, "client", "PubKS", cltPk);
                cout << "-> Client PubKS Received and Stored ..." << endl;

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
                auto finalTemp = receiveMapOfVectComponent(withEnrollServer, dlog, elgamal,elgamalTH);
                writeTemplate(dirUser, finalTemp);
                writeCSVNew(out_file, localStart, false);
                writeCSVNew(out_file, globalStart, true);
                cout << "-> Template Received and Stored ..." << endl;
                cout << "======= Enrollment END =======" << endl;  

            }

             





        }
        else if(stoi(argv[1]) == 1){            

            
            server->join(500, 5000);

            int count = stoi(argv[3]);
            int step = stoi(argv[4]);

            for (size_t i = 1; i < count; i=i+step)
            {
                
                out_file.open(verLogTimer, ios::app);
                if (!out_file)
                {
                    throw "Error creating file"s;
                }
                cout << "======= Verification =======" << endl;
                localStart = std::chrono::system_clock::now();
                globalStart = localStart;


                cout << "--> Step 1: User's existence verification ..." << endl;
                auto userId = receiveBigint(server);
                dirUser = dirServer +"/MAL/USERS/user"+userId.str()+"/";
                keyStorage = dirUser+"keystorage.txt";
                path p(dirUser+userId.str()+"Template.txt");
                if(!exists(p)){            
                    server->writeWithSize("Unregistered");
                    throw "Unregistered User"s; 
                }
                server->writeWithSize("Registered");          
                cout << "User " << userId << " exists" << endl;
                writeCSVNew(out_file, localStart, false);

                
                localStart = std::chrono::system_clock::now();
                auto s2 = readBigintFromfile(keyStorage, "server", "PrivTH");
                ElGamalPrivateKey serPrivKeyTH(s2);
                shared_ptr<PrivateKey> serverPrivKeyTH = make_shared<ElGamalPrivateKey>(serPrivKeyTH);
                auto clientPKeyTH = readPubKeyFromfile(keyStorage, dlog, "client", "PubTH");  
                auto serverPKeyTH = readPubKeyFromfile(keyStorage, dlog, "server", "PubTH");             
                auto jointPubKey = readPubKeyFromfile(keyStorage, dlog, "joint", "jointTH"); 
                elgamalTH->setKey(jointPubKey, serverPrivKeyTH);

                auto clientPKey = readPubKeyFromfile(keyStorage, dlog, "client", "PubKS");
                elgamal->setKey(clientPKey);  

                auto thresholdEncSet = readVectCipherFromFile(dirUser+"thresholdEncSet.txt", dlog);
                
                writeCSVNew(out_file, localStart, false);
                cout << "--> Keys and Threshold Set loaded ..." << endl;
            
                cout << "--> Step 1: DONE ..." << endl;
                cout << endl;          


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 2: Probe verification ..." << endl;
                localStart = std::chrono::system_clock::now();

                auto probeEnc = receiveVectElGamalCipher(server, dlog, elgamal);
                auto indexCompVect = receiveIntVect(server);

                proofStart = std::chrono::system_clock::now();
                resultBool = zkPoKMultiANDPlainVerifier_parallel(server, configFile, curve, clientPKey, probeEnc);
                str = receiveStr(server);
                if( "Incorrect Commitment" == str){
                    throw "Incorrect Commitment"s; 
                }          
                cout << str << endl;

                if(resultBool == false){
                    server->writeWithSize("Proof Failure");
                    throw "Proof Failure"s;
                }
                server->writeWithSize("Successful Proof");
                writeCSVNew(out_file, proofStart, false);
                cout << "Successful Proof" << endl;
                writeCSVNew(out_file, localStart, false);
                cout << "--> Step 2: DONE ..." << endl;
                cout << endl;


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 3: Protected individual scores exchange ..." << endl;
                localStart = std::chrono::system_clock::now();

                auto requestedComp = readSpecificCompTemplate(dirUser+userId.str()+"Template.txt", dlog, indexCompVect);            
                sendVectComponent(server, requestedComp);
                auto colEncFromTemp = extractColEncFromTemp_parallel(requestedComp);
                auto scoreEncFromTemp = extractScoreEncFromTemp_parallel(requestedComp);  
                // auto colEncFromTemp = extractColEncFromTemp(requestedComp);
                // auto scoreEncFromTemp = extractScoreEncFromTemp(requestedComp);   
            
                proofStart = std::chrono::system_clock::now(); 
                str = receiveStr(server);
                if( "Incorrect Signature" == str){
                    throw "Incorrect Signature"s; 
                }          
                cout << str << endl;
                writeCSVNew(out_file, proofStart, false);

                auto cipherDecZeroVect = subtractTwoCipherVect_parallel(configFile, curve, clientPKey, colEncFromTemp, probeEnc);   
                // auto cipherDecZeroVect = subtractTwoCipherVect(dlog, elgamal, colEncFromTemp, probeEnc);   
                
                proofStart = std::chrono::system_clock::now(); 
                resultBool = niZKMultiANDDecZeroVerifier_parallel(server, configFile, curve, clientPKey, cipherDecZeroVect);
                if(resultBool == false){
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

                auto finalScore = multiplyCiphersOfVect(elgamalTH, scoreEncFromTemp);
                // auto finalScore = multiplyCiphersOfVect_parallel(configFile, curve, jointPubKey, scoreEncFromTemp);
                auto comparisonVect = subtractOneCipherFromCipherVect_parallel(configFile, curve, jointPubKey, thresholdEncSet, finalScore);

                auto blindRVect = generateVectBigintRand_parallel(q, comparisonVect.size());            
                auto comparisonVectBlinded = blindVectCipherElGamal_parallel(configFile, curve, comparisonVect, blindRVect);
                auto partialDecBlindedCompVect = partiallyDecryptVectCiphers_parallel(configFile, curve, jointPubKey, serverPrivKeyTH, comparisonVectBlinded);

                
                // auto comparisonVect = subtractOneCipherFromCipherVect(dlog, elgamalTH, thresholdEncSet, finalScore);
                // auto blindRVect = generateVectBigintRand(q, comparisonVect.size());            
                // auto comparisonVectBlinded = blindVectCipherElGamal(dlog, comparisonVect, blindRVect);
                // auto partialDecBlindedCompVect = partiallyDecryptVectCiphers(elgamalTH, comparisonVectBlinded);

                sendVectElGamalCipher(server, comparisonVectBlinded);
                sendVectGpElt(server, partialDecBlindedCompVect);

                proofStart = std::chrono::system_clock::now();
                // resultInt = niZKMultiANDBlindedProver_parallel(server, configFile, curve, jointPubKey, comparisonVect, blindRVect);
                resultInt = niZKMultiANDBlindedProver(server, dlog, elgamalTH, comparisonVect, blindRVect);
                if( resultInt == 0){
                    throw "Proof Failure"s;
                }
                cout << "Successful Proof" << endl;
                writeCSVNew(out_file, proofStart, false);

                proofStart = std::chrono::system_clock::now();
                // resultInt = niZKMultiANDPartialDecProver_parallel(server, configFile, curve, serverPKeyTH, comparisonVectBlinded, s2);
                resultInt = niZKMultiANDPartialDecProver(server, dlog, serverPKeyTH, comparisonVectBlinded, s2);
                if( resultInt == 0){
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
                
                str = receiveStr(server);         
                cout << str << endl;
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

    cout << "END Malicious Server ..." << endl;
    return 0;

}