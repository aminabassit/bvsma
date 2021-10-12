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



/* 
* SEMI-HONEST CLIENT
*/




int main(int argc, char* argv[]){
    cout << "Run Semi-Honest Client ..." << endl;


    boost::asio::io_service io_service;

    auto clientIp = IpAddress::from_string("127.0.0.1");
	auto serverIp = IpAddress::from_string("127.0.0.1");
    
    SocketPartyData clientParty(clientIp, 1222);
    SocketPartyData serverParty(serverIp, 1223);	 

    shared_ptr<CommParty> client = make_shared<CommPartyTCPSynced>(io_service, clientParty, serverParty);


    boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
    
    
    string dirClient = "../../../data/client/"+ string(argv[6]) +"/P"+ string(argv[2]);
    string enrLogTimer = dirClient +"/SHenrClt"+"P"+ string(argv[2])+ string(argv[6]) +".csv";
    string verLogTimer = dirClient +"/SHverClt"+"P"+ string(argv[2])+ string(argv[6]) +".csv";
    string resultMatch = dirClient +"/SHresultMatch"+"P"+ string(argv[2])+ string(argv[6]) +".csv";
    string keyStorage;
    string dirUser;
    
    
    

    


    
    
    string qBinsFile = "../../../data/lookupTables/"+ string(argv[6]) +"/"+ string(argv[6]) +"_qbins.csv";
    string sensorFile = string(argv[5]);
    string dirHELR = "../../../data/lookupTables/"+ string(argv[6]) +"/";

    vector<int> maxNFQ(stoi(argv[7]), stoi(argv[8]));


    string configFile = "../../../../libscapi/include/configFiles/NISTEC.txt";
    string curve = "P-"+string(argv[2]);


	auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();


    auto random = get_seeded_prg();

    shared_ptr<ElGamalOnGroupElementEnc> elgamalTH = make_shared<ElGamalOnGroupElementEnc>(dlog);
    



    
    unsigned int seedClt = 149423;

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

            client->join(500, 5000);             
            
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
                dirUser = dirClient +"/SH/USERS/user"+userId.str();
                path pathUser(dirUser);
                create_directory(pathUser);
                dirUser = dirUser+"/";
                keyStorage = dirUser+"keystorage.txt";

                sendBigint(client, userId);
                cout << "-> User " << userId << " Enrollment Request ..." << endl; 
  
                
                auto pairTH = elgamalTH->generateKey();            
                auto s1 = dynamic_cast<ElGamalPrivateKey*>(pairTH.second.get())->getX();
                writeBigintinFile(keyStorage, "client", "PrivTH", s1);
                
                auto clientPKeyTH = pairTH.first;
                writePubKeyinFile(keyStorage, "client", "PubTH", clientPKeyTH);
                cout << "-> Client PrivTH and PubTH Generated and Stored ..." << endl;
                
                            
                
                sendElGamalPubKey(client, clientPKeyTH);
                cout << "-> Client PubTH Sent ..." << endl;
                
                auto serverPKeyTH = receiveElGamalPubKey(client, dlog, elgamalTH);  
                writePubKeyinFile(keyStorage, "server", "PubTH", serverPKeyTH); 
                cout << "-> Server PubTH Received and Stored ..." << endl; 



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

                auto quantizedSample = quantizefeaturesFPD(qBinsFile, sample);
                auto userTemplate = encryptRowsFromHELR(dirHELR, dlog, elgamalTH, quantizedSample);

                sendMapElGamalCipher(client, userTemplate);
                writeCSVNew(out_file, localStart, false);   
                writeCSVNew(out_file, globalStart, true);
                cout << "-> Template Generated and Sent ..." << endl;
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

                cout << "--> Step 1: User's existence verification ..." << endl; 

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
                
                dirUser = dirClient +"/SH/USERS/user"+userId.str()+"/";
                keyStorage = dirUser+"keystorage.txt"; 

                auto s1 = readBigintFromfile(keyStorage, "client", "PrivTH");
                ElGamalPrivateKey cltPrivKeyTH(s1);
                shared_ptr<PrivateKey> clientPrivKeyTH = make_shared<ElGamalPrivateKey>(cltPrivKeyTH);
                auto serverPKeyTH = readPubKeyFromfile(keyStorage, dlog, "server", "PubTH");              
                auto jointPubKey = readPubKeyFromfile(keyStorage, dlog, "joint", "jointTH"); 
                elgamalTH->setKey(jointPubKey, clientPrivKeyTH); 

              
                writeCSVNew(out_file, localStart, false);
                cout << "----> Keys loaded ..." << endl;
                cout << "--> Step 1: DONE ..." << endl;
                cout << endl;          


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 2: Select, Mult, and Randomize the Scores ..." << endl;
                localStart = std::chrono::system_clock::now();


                auto userTemplateReceived = receiveMapElGamalCipher(client, dlog, elgamalTH);
                cout << "----> Template Received ##############" << endl;

                auto sample = pairSample.second;
                vector<int> rawProbe = quantizefeaturesFPD(qBinsFile, sample);  
                auto scoreEncFromTemp = pickSpecificCiphers(rawProbe, userTemplateReceived);
                auto sumScores = multiplyCiphersOfVect(elgamalTH, scoreEncFromTemp);
                auto r = getRandomInRange(1, q - 1, random.get());        
                auto identityEnc = elgamalTH->encrypt(make_shared<GroupElementPlaintext>(dlog->getIdentity()), r);
                auto finalScore = elgamalTH->multiply(sumScores.get(), identityEnc.get());

                sendElGamalCipher(client, finalScore);


                writeCSVNew(out_file, localStart, false);
                cout << "--> Step 2: DONE ..." << endl;
                cout << endl;


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 3: Receive Partial Comparison ..." << endl;
                localStart = std::chrono::system_clock::now();

                auto partialDecBlindedCompVect = receiveVectElGamalCipher(client, dlog, elgamalTH);

                writeCSVNew(out_file, localStart, false);
                cout << "--> Step 3: DONE ..." << endl;
                cout << endl;


                cout << "-------------------------------------------" << endl;
                cout << "--> Step 4: Comparison Result ..." << endl;
                localStart = std::chrono::system_clock::now();

                resultBool = finalDecryptionANDMatchSH(elgamalTH, partialDecBlindedCompVect);


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
                cout << "--> Step 4: DONE ..." << endl;
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

    cout << "END Semi-Honest Client ..." << endl;
    return 0;

}