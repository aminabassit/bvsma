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

// ./server 0 192 501 1 BMDB 14 86
// ./server 0 224 501 1 BMDB 14 86
// ./server 0 256 501 1 BMDB 14 86

// ./server 0 192 501 1 PUT -53 136
// ./server 0 224 501 1 PUT -53 136
// ./server 0 256 501 1 PUT -53 136

// ./server 0 192 501 1 FRGC -1 75
// ./server 0 224 501 1 FRGC -1 75
// ./server 0 256 501 1 FRGC -1 75







/* 
* SEMI-HONEST SERVER
*/




int main(int argc, char* argv[]){
    cout << "Run Semi-Honest Server ..." << endl;

    boost::asio::io_service io_service;
    
    auto clientIp = IpAddress::from_string("127.0.0.1");
	auto serverIp = IpAddress::from_string("127.0.0.1");
    
    SocketPartyData clientParty(clientIp, 1222);
    SocketPartyData serverParty(serverIp, 1223);
	

    shared_ptr<CommParty> server = make_shared<CommPartyTCPSynced>(io_service, serverParty, clientParty); 
   
    boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));


    
    string dirServer = "../../../data/server/"+ string(argv[5]) +"/P"+ string(argv[2]);
    string enrLogTimer = dirServer +"/SHenrSer"+"P"+ string(argv[2])+ string(argv[5]) +".csv";
    string verLogTimer = dirServer +"/SHverSer"+"P"+ string(argv[2])+ string(argv[5]) +".csv";
    string keyStorage;
    string dirUser;
    

    string configFile = "../../../../libscapi/include/configFiles/NISTEC.txt";
    string curve = "P-"+string(argv[2]);
    

    auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();

    auto random = get_seeded_prg();

    shared_ptr<ElGamalOnGroupElementEnc> elgamalTH = make_shared<ElGamalOnGroupElementEnc>(dlog);
    
    unsigned int seedTH = 145523;

    int resultInt;
    bool resultBool;
    string str;

    std::chrono::time_point<std::chrono::system_clock> globalStart;
    std::chrono::time_point<std::chrono::system_clock> localStart;

    std::ofstream out_file;



    
    try
    {
        
        if (stoi(argv[1]) == 0)
        {
            
            int count = stoi(argv[3]);
            int step = stoi(argv[4]);

            server->join(500, 5000); 


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


                auto userId = receiveBigint(server);
                cout << "-> User " << userId << " Enrollment Request ..." << endl;
                dirUser = dirServer +"/SH/USERS/user"+userId.str();
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
                
                sendElGamalPubKey(server, serverPKeyTH);
                cout << "-> Server PubTH Sent ..." << endl;

                
                auto clientPKeyTH = receiveElGamalPubKey(server, dlog, elgamalTH);  
                writePubKeyinFile(keyStorage, "client", "PubTH", clientPKeyTH); 
                cout << "-> Client PubTH Received and Stored ..." << endl; 


                auto serPKeyTH = dynamic_cast<ElGamalPublicKey*>(serverPKeyTH.get())->getH();
                auto cltPKeyTH = dynamic_cast<ElGamalPublicKey*>(clientPKeyTH.get())->getH();
                auto jointH = dlog->multiplyGroupElements(cltPKeyTH.get(),serPKeyTH.get());    
                ElGamalPublicKey jointPK(jointH);
                shared_ptr<PublicKey> jointPubKey = make_shared<ElGamalPublicKey>(jointPK);
                elgamalTH->setKey(jointPubKey, pairTH.second);
                writePubKeyinFile(keyStorage, "joint", "jointTH", jointPubKey); 
                writeCSVNew(out_file, localStart, false);
                cout << "-> Joint jointTH Received and stored ..." << endl;         
                cout << "----> Keys Establishment DONE ..." << endl;                        


                cout << "-------------------------------------------" << endl;



                localStart = std::chrono::system_clock::now();
                auto userTemplate = receiveMapElGamalCipher(server, dlog, elgamalTH);

                writeTemplateSH(dirUser, userTemplate);

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
                dirUser = dirServer +"/SH/USERS/user"+userId.str()+"/";
                keyStorage = dirUser+"keystorage.txt";
                path p(dirUser+"Template.txt");
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
 

                /*  */

                biginteger threshold(stoi(argv[6]));
                size_t lenTH = stoi(argv[7]);
                auto thresholdEncSet = generateThresholdEncSet_parallel(seedTH, configFile, curve, jointPubKey, threshold, lenTH);
                // auto thresholdEncSet = generateThresholdEncSet(seedTH, dlog, elgamalTH, threshold, lenTH);
                
                cout << "-> Threshold Set Encrypted and Permuted ..." << endl;
                /*  */


                writeCSVNew(out_file, localStart, false);
                cout << "--> Keys and Threshold Set loaded ..." << endl;
            
                cout << "--> Step 1: DONE ..." << endl;
                cout << endl;          


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 2: Fetch Template ..." << endl;
                localStart = std::chrono::system_clock::now();
                //read map
                auto userTemplate = readTemplateSH(dirUser+"Template.txt", dlog) ;
                sendMapElGamalCipher(server, userTemplate);

                writeCSVNew(out_file, localStart, false);
                cout << "--> Step 2: DONE ..." << endl;
                cout << endl;


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 3: Receive Final Score ..." << endl;
                localStart = std::chrono::system_clock::now();



                auto finalScore = receiveElGamalCipher(server, dlog, elgamalTH);          

                writeCSVNew(out_file, localStart, false);
                cout << "--> Step 3: DONE ..." << endl;
                cout << endl;


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 4: Comparison of the similarity score with the threshold set ..." << endl;
                localStart = std::chrono::system_clock::now();

                auto comparisonVect = subtractOneCipherFromCipherVect_parallel(configFile, curve, jointPubKey, thresholdEncSet, finalScore);
                auto blindRVect = generateVectBigintRand_parallel(q, comparisonVect.size());        
                auto comparisonVectBlinded = blindVectCipherElGamal_parallel(configFile, curve, comparisonVect, blindRVect);
                auto partialDecBlindedCompVect = elgamalPartialDecryption_parallel(configFile, curve, jointPubKey, serverPrivKeyTH, comparisonVectBlinded); 
                // auto comparisonVect = subtractOneCipherFromCipherVect(dlog, elgamalTH, thresholdEncSet, finalScore);
                // auto blindRVect = generateVectBigintRand(q, comparisonVect.size());        
                // auto comparisonVectBlinded = blindVectCipherElGamal(dlog, comparisonVect, blindRVect);
                // auto partialDecBlindedCompVect = elgamalPartialDecryption(elgamalTH, comparisonVectBlinded);       
                
                sendVectElGamalCipher(server, partialDecBlindedCompVect);

            
                writeCSVNew(out_file, localStart, false);
                cout << "--> Step 4: DONE ..." << endl;
                cout << endl;


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 5: Comparison Result ..." << endl;
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

    cout << "END Semi-Honest Server ..." << endl;
    return 0;

}