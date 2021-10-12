#include <boost/filesystem.hpp>


#include "bvsma/include/functions.hpp"
#include "bvsma/include/ZKProofs.hpp"
#include "bvsma/include/SchnorrSignature.hpp"
#include "bvsma/include/fileFunctions.hpp"
#include "bvsma/include/functionsParallel.hpp"


using namespace boost::filesystem;
using namespace std;
typedef unsigned char byte;



    // ./enrollmentServer 192 501 1 14 86 BMDB    
    // ./enrollmentServer 224 501 1 14 86 BMDB 
    // ./enrollmentServer 256 501 1 14 86 BMDB 

    // ./enrollmentServer 192 501 1 -53 136 PUT    
    // ./enrollmentServer 224 501 1 -53 136 PUT 
    // ./enrollmentServer 256 501 1 -53 136 PUT 

    // ./enrollmentServer 192 501 1 -1 75 FRGC    
    // ./enrollmentServer 224 501 1 -1 75 FRGC 
    // ./enrollmentServer 256 501 1 -1 75 FRGC 


int main(int argc, char* argv[]){
    cout << "Run Enrollment Server ..." << endl;

    boost::asio::io_service io_service;

    auto clientIp = IpAddress::from_string("127.0.0.1");
	auto serverIp = IpAddress::from_string("127.0.0.1");
    auto enrollServerIp = IpAddress::from_string("127.0.0.1");
    
    SocketPartyData clientParty(clientIp, 8002);
    SocketPartyData serverParty(serverIp, 8003);

    SocketPartyData enrollServerParty1(enrollServerIp, 1224); 
    SocketPartyData enrollServerParty2(enrollServerIp, 8004); 

    shared_ptr<CommParty> withClient = make_shared<CommPartyTCPSynced>(io_service, enrollServerParty1, clientParty);
    shared_ptr<CommParty> withServer = make_shared<CommPartyTCPSynced>(io_service, enrollServerParty2, serverParty);



    boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));



    string dirEnrServer = "../../../data/enrollmentServer/"+ string(argv[6]) +"/P"+ string(argv[1]);
    string enrLogTimer = dirEnrServer +"/MALenrollServerLogTimer.csv";
  
    string dirUser;
    string keyStorage;
    std::ofstream out_file;



    string configFile = "../../../../libscapi/include/configFiles/NISTEC.txt";
    string curve = "P-"+string(argv[1]);


	auto dlog = make_shared<OpenSSLDlogECFp>(configFile, curve);
    auto g = dlog->getGenerator();
    auto q = dlog->getOrder();

    shared_ptr<ElGamalOnGroupElementEnc> elgamalTH = make_shared<ElGamalOnGroupElementEnc>(dlog);
    shared_ptr<ElGamalOnGroupElementEnc> elgamal = make_shared<ElGamalOnGroupElementEnc>(dlog);  


    unsigned int seedTH = 145523;


    int resultInt;
    bool resultBool;

    string str;

    

    std::chrono::time_point<std::chrono::system_clock> globalStart;
    std::chrono::time_point<std::chrono::system_clock> localStart;



    
    try
    {
        
        withClient->join(500, 5000); 
        withServer->join(500, 5000);

        int count = stoi(argv[2]);
        int step = stoi(argv[3]);

        

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

            auto userId = receiveBigint(withClient);
            sendBigint(withServer, userId);
            cout << "-> User " << userId << " Enrollment Request ..." << endl;
            dirUser = dirEnrServer +"/MAL/USERS/user"+userId.str();
            path pathUser(dirUser);
            create_directory(pathUser);
            dirUser = dirUser+"/";
            keyStorage = dirUser+"keystorage.txt";

            auto cltPk = receiveElGamalPubKey(withClient, dlog, elgamal);
            writePubKeyinFile(keyStorage, "client", "PubKS", cltPk);
            cout << "-> Client PubKS Received and Stored ..." << endl;          
            
            auto clientPKeyTH = receiveElGamalPubKey(withClient, dlog, elgamalTH);
            writePubKeyinFile(keyStorage, "client", "PubTH", clientPKeyTH);
            cout << "-> Client PubTH Received and Stored ..." << endl;

            auto serverPKeyTH = receiveElGamalPubKey(withServer, dlog, elgamalTH);
            writePubKeyinFile(keyStorage, "server", "PubTH", serverPKeyTH);
            cout << "-> Server PubTH Received and Stored ..." << endl;
            
            auto serPKeyTH = dynamic_cast<ElGamalPublicKey*>(serverPKeyTH.get())->getH();
            auto cltPKeyTH = dynamic_cast<ElGamalPublicKey*>(clientPKeyTH.get())->getH();
            auto jointH = dlog->multiplyGroupElements(cltPKeyTH.get(),serPKeyTH.get());    
            ElGamalPublicKey jointPK(jointH);
            shared_ptr<PublicKey> jointPubKey = make_shared<ElGamalPublicKey>(jointPK);
            elgamalTH->setKey(jointPubKey);
            writePubKeyinFile(keyStorage, "joint", "jointTH", jointPubKey);
            cout << "-> Joint jointTH Computed and Stored ..." << endl;

            SchnorrSignature schnorr(dlog);
            schnorr.KeyGen();
            writeGPELTinFile(keyStorage, "enrollmentServer", "VerKey", schnorr.getVerifKey());
            writeBigintinFile(keyStorage, "enrollmentServer", "SigKey", schnorr.getSignKey());
            cout << "-> EnrollmentServer VerKey and SigKey Generated and Stored ..." << endl;

            sendGpElt(withClient, schnorr.getVerifKey());
            sendElGamalPubKey(withClient, serverPKeyTH); 
            sendElGamalPubKey(withClient, jointPubKey); 
            cout << "-> VerKey, ServerPubTH and jointTH Sent to Client ..." << endl;

            sendGpElt(withServer, schnorr.getVerifKey());
            sendElGamalPubKey(withServer, clientPKeyTH);
            sendElGamalPubKey(withServer, cltPk);  
            sendElGamalPubKey(withServer, jointPubKey);
            writeCSVNew(out_file, localStart, false);
            cout << "-> VerKey, ClientPubTH, PubKS and jointTH Sent to Server ..." << endl; 
            cout << "----> Keys Establishment DONE ..." << endl;


            cout << "-------------------------------------------" << endl;


            localStart = std::chrono::system_clock::now();
            biginteger threshold(stoi(argv[4]));
            size_t lenTH = stoi(argv[5]);
            auto thresholdEncSet = generateThresholdEncSet(seedTH, dlog, elgamalTH, threshold, lenTH);
            writeVectCipherinFile(dirUser+"thresholdEncSet.txt", thresholdEncSet);
            cout << "-> Threshold Set Encrypted, Permuted and Stored ..." << endl; 
            sendVectElGamalCipher(withClient, thresholdEncSet);    
            sendVectElGamalCipher(withServer, thresholdEncSet);  
            cout << "-> Threshold Set Encrypted and Permuted Sent to Client and Server ..." << endl;
            writeCSVNew(out_file, localStart, false);        
            cout << "----> Threshold Set Encrypted DONE ..." << endl;

            
            cout << "-------------------------------------------" << endl;


            localStart = std::chrono::system_clock::now();
            auto partialTemplate = receiveMapOfVectComponent(withClient, dlog, elgamal, elgamalTH);
            auto finalTemp = generateTemplate(schnorr, partialTemplate);
            sendMapOfVectComponent(withServer, finalTemp);
            writeTemplate(dirUser, finalTemp);
            writeCSVNew(out_file, localStart, false);
            writeCSVNew(out_file, globalStart, true);
            cout << "-> Template Generated, Stored and Sent to Server ..." << endl;
            cout << "----> Template Generation DONE ..." << endl;
            cout << "======= Enrollment END =======" << endl;


        }

        
        

        
    }
    catch (const logic_error& e) {
        io_service.stop();
        t.join(); 
		cerr << e.what();        
	} 
    catch (string &e){
        io_service.stop();
        t.join(); 
        cerr << e << endl; 
    }
    
    io_service.stop();
    t.join(); 

    cout << "END Enrollment Server ..." << endl;
    return 0;

}