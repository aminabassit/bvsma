
#include "bvsma/include/fileFunctions.hpp"

using namespace std;



pair<unsigned long, vector<double>> readSampleWithIDInLine(string filename, int sample){
    vector<double> unQuantizedFeatures;
    ifstream in_file;
    string line{}, str{};
    vector<string> strVect, strVect1;
    unsigned long userID;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    in_file.seekg(ios::beg);
    for(size_t n=0;n<sample-1;++n){
    in_file.ignore(std::numeric_limits<streamsize>::max(), '\n');
    }
    getline(in_file, line);
    strVect = explode(line, ',');
    strVect1 = explode(strVect.at(0), '_');
    str = strVect1.at(0)+strVect1.at(1);
    userID = stoul(str);
    strVect.erase(strVect.begin());
    for(auto s : strVect){
        unQuantizedFeatures.push_back(stold(s));
    }
    in_file.close();
    return make_pair(userID, unQuantizedFeatures);
}

// For BMDB PUT FRGC

pair<unsigned long, vector<double>> readSampleWithIDInLineFPD(string filename, int sample){
    vector<double> unQuantizedFeatures;
    ifstream in_file;
    string line{}, str{};
    vector<string> strVect, strVect1;
    unsigned long userID;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    in_file.seekg(ios::beg);
    for(size_t n=0;n<sample-1;++n){
    in_file.ignore(std::numeric_limits<streamsize>::max(), '\n');
    }
    getline(in_file, line);
    strVect = explode(line, ',');
    userID = stoul(strVect.at(0));
    strVect.erase(strVect.begin());
    for(auto s : strVect){
        unQuantizedFeatures.push_back(stold(s));
    }
    in_file.close();
    return make_pair(userID, unQuantizedFeatures);
}


biginteger readBigintFromfile(string filename, string partyID, string typeKey){
    ifstream in_file; 
    string line{};
    vector<string> strVect;
    strVect.resize(0);
    string str;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    while(getline(in_file, line)) {
        strVect = explode(line, ',');
        if(strVect.at(0) == partyID && strVect.at(1) == typeKey){
            str = strVect.at(2);            
            break;
        }     

    }
    in_file.close();
    return biginteger(str);
}

biginteger readBigintFromfileInline(string filename, unsigned int num){
    ifstream in_file; 
    string line{};
    vector<string> strVect;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    in_file.seekg(ios::beg);
    for(size_t n=0;n<num-1;++n){
    in_file.ignore(std::numeric_limits<streamsize>::max(), '\n');
    }
    getline(in_file, line);
    strVect = explode(line, ','); 
    in_file.close();
    return biginteger(strVect.at(2));
}


shared_ptr<GroupElement> readGPEltFromfile(string filename, shared_ptr<OpenSSLDlogECFp> dlog, string partyID, string typeKey){
    ifstream in_file; 
    string line{};
    vector<string> strVect;
    strVect.resize(0);
    shared_ptr<GroupElement> gpElt;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    while(getline(in_file, line)) {
        strVect = explode(line, ',');
        if(strVect.at(0) == partyID && strVect.at(1) == typeKey){
            auto v = explode(strVect.at(2), ':');
            vector<biginteger> biginVect;
            biginVect.push_back(biginteger(v.at(0)));
            biginVect.push_back(biginteger(v.at(1)));
            gpElt = dlog->generateElement(true, biginVect);
            break;
        }     

    }
    in_file.close();
    return gpElt;
}

shared_ptr<GroupElement> readGPEltFromfileInline(string filename, shared_ptr<OpenSSLDlogECFp> dlog, unsigned int num){
    ifstream in_file; 
    string line;
    vector<string> strVect;
    shared_ptr<GroupElement> gpElt;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    in_file.seekg(ios::beg);
    for(size_t n=0;n<num-1;++n){
    in_file.ignore(std::numeric_limits<streamsize>::max(), '\n');
    }
    getline(in_file, line);
    strVect = explode(line, ','); 
    auto v = explode(strVect.at(2), ':');
    vector<biginteger> biginVect;
    biginVect.push_back(biginteger(v.at(0)));
    biginVect.push_back(biginteger(v.at(1)));
    gpElt = dlog->generateElement(true, biginVect);
    in_file.close();
    return gpElt;
}

vector<shared_ptr<AsymmetricCiphertext>> readVectCipherFromFile(string filename,  shared_ptr<OpenSSLDlogECFp> dlog){
    ifstream in_file; 
    string line{};
    vector<string> strVect;
    vector<shared_ptr<GroupElement>> vectGpElt;
    vector<shared_ptr<AsymmetricCiphertext>> cipherVect;
    shared_ptr<AsymmetricCiphertext> cipher;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    while(getline(in_file, line)) {
        strVect = explode(line, '=');
        vectGpElt = strToVectGpElt(dlog, strVect.at(1));
        cipher = make_shared<ElGamalOnGroupElementCiphertext>(vectGpElt.at(0), vectGpElt.at(1));     
        cipherVect.push_back(cipher);  
    }
    in_file.close();
    return cipherVect;
}

shared_ptr<PublicKey> readPubKeyFromfile(string filename, shared_ptr<OpenSSLDlogECFp> dlog, string partyID, string typeKey){
    auto gpElt = readGPEltFromfile(filename, dlog, partyID, typeKey);
    return make_shared<ElGamalPublicKey>(gpElt);
}

shared_ptr<PublicKey> readPubKeyFromfileInLine(string filename, shared_ptr<OpenSSLDlogECFp> dlog, unsigned int num){
    auto gpElt = readGPEltFromfileInline(filename, dlog, num);
    return make_shared<ElGamalPublicKey>(gpElt);
}

vector<int> readSpecificPermutation(string filename, vector<int> rawProbe){
    vector<int> permutedProbe;
    permutedProbe.resize(0);
    ifstream in_file; 
    string line{};
    vector<string> strVect1, strVect;
    strVect1.resize(0);
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    while(getline(in_file, line)) {
        strVect1 = explode(line, ':');
        auto i = stoi(strVect1.at(0));
        strVect = explode(strVect1.at(1), ',');
        permutedProbe.push_back(stoi(strVect.at(rawProbe.at(i))));       
    }
    in_file.close();

    return permutedProbe;
}


vector<Component> readSpecificCompTemplate(string filename, shared_ptr<OpenSSLDlogECFp> dlog, vector<int> indexComp){
    vector<Component> compPicked;
    compPicked.resize(indexComp.size());

    ifstream in_file; 
    string line{};
    vector<string> strVect1, strIJ, strVect;
    strVect1.resize(0);

    biginteger userId; 
    biginteger indexC;  
    shared_ptr<AsymmetricCiphertext> colEnc;    
    shared_ptr<AsymmetricCiphertext> scoreEnc;
    Signature colEncSig;    
    Signature scoreEncSig; 

    vector<shared_ptr<GroupElement>> vectGpElt;

    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    size_t i = 0;
    while(getline(in_file, line)){
        strVect1 = explode(line, '=');
        strIJ = explode(strVect1.at(0), ',');
        auto posI = stoi(strIJ.at(0));
        auto posJ = stoi(strIJ.at(1));
        if((i == posI) && (indexComp.at(i) == posJ)){
            strVect = explode(strVect1.at(1), ';');
            userId = biginteger(strVect.at(0));
            indexC = biginteger(strVect.at(1));
            vectGpElt = strToVectGpElt(dlog, strVect.at(2));
            colEnc = make_shared<ElGamalOnGroupElementCiphertext>(vectGpElt.at(0), vectGpElt.at(1));
            vectGpElt.resize(0);
            vectGpElt = strToVectGpElt(dlog, strVect.at(3));
            scoreEnc = make_shared<ElGamalOnGroupElementCiphertext>(vectGpElt.at(0), vectGpElt.at(1));
            vectGpElt.resize(0);
            colEncSig = Signature(strVect.at(4));
            scoreEncSig = Signature(strVect.at(5));
            compPicked.at(i) = Component(userId, indexC, colEnc, scoreEnc, colEncSig, scoreEncSig);
            i++;
        }       
              
    }
    in_file.close();
    return compPicked;
}

map<int, vector<shared_ptr<AsymmetricCiphertext>>> readTemplateSH(string filename, shared_ptr<OpenSSLDlogECFp> dlog){
    map<int, vector<shared_ptr<AsymmetricCiphertext>>> templateSH;

    ifstream in_file; 
    string line{};
    vector<string> strVect1, strVect;
    strVect1.resize(0);

    vector<shared_ptr<AsymmetricCiphertext>> rowVect;
    vector<shared_ptr<GroupElement>> vectGpElt;

    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    size_t rowlen;
    int i;
    
    while(getline(in_file, line)){
        strVect1 = explode(line, '=');
        i = stoi(strVect1.at(0));
        strVect = explode(strVect1.at(1), ';');
        rowlen = strVect.size();
        rowVect.resize(rowlen);
        for (size_t j = 0; j < rowlen; j++)
        {
            vectGpElt = strToVectGpElt(dlog, strVect.at(j));
            rowVect.at(j) = make_shared<ElGamalOnGroupElementCiphertext>(vectGpElt.at(0), vectGpElt.at(1));
            vectGpElt.resize(0);
        }
        templateSH[i] = rowVect;
        rowVect.resize(0);
              
    }
    in_file.close();
    return templateSH;
}


vector<int> quantizefeatures(string filename, vector<double> unQuantizedFeatures){
    ifstream in_file; 
    string line;
    vector<string> strVect;
    string str;
    vector<int> quantizedFeatures;
    int count, len, feature = 0;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    while(getline(in_file, line)) {
        strVect = explode(line, ',');
        len = strVect.size();
        count = 0;
        while( stold(strVect.at(count)) <= unQuantizedFeatures.at(feature)){
            count++;
            if(count == len){
                break;
            }
        }
        quantizedFeatures.push_back(count);
        feature++;
    }
    in_file.close();
    return quantizedFeatures;
}

// For BMDB PUT FRGC

vector<int> quantizefeaturesFPD(string filename, vector<double> unQuantizedFeatures){
    ifstream in_file; 
    string line;
    vector<string> strVect;
    string str;
    auto numFeat = unQuantizedFeatures.size();
    vector<int> quantizedFeatures;
    int count, len, feature = 0;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    while(getline(in_file, line)) {
        strVect = explode(line, ',');
        len = strVect.size();
        for (size_t i = 0; i < numFeat; i++)
        {
            auto feature = unQuantizedFeatures.at(i);
            count = 0;
            while( stold(strVect.at(count)) <= feature){
                count++;
                if(count == len){
                    break;
                }
            }
            quantizedFeatures.push_back(count);
        }
    }
    in_file.close();
    return quantizedFeatures;
}


vector<biginteger> readRowfromHELRFile(string dir, int feature, int row){
    string filename = dir+"HELR"+to_string(feature)+".csv";
    ifstream in_file; 
    string line;
    vector<string> strVect;
    vector<biginteger> rowVect;
    string str;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    for(int i = -1; i<row; i++){
        getline(in_file, line);
    }
    strVect = explode(line, ',');
    for(string s : strVect){
        rowVect.push_back(biginteger(stoi(s)));
    }
    in_file.close();
    return rowVect;
}

vector<int> readMaxNFQ(string filename){
    ifstream in_file; 
    string line;
    vector<string> strVect;
    vector<int> maxNFQ;
    string str;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    getline(in_file, line);
    strVect = explode(line, ',');
    for(auto s : strVect){
        maxNFQ.push_back(stoi(s));
    }
    in_file.close();
    return maxNFQ;
}


vector<double> readSample(string filename, int sample){
    vector<double> unQuantizedFeatures;
    ifstream in_file;
    string line{};
    vector<string> strVect;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    for(int i = -1; i<sample; i++){
        getline(in_file, line);
    }
    strVect = explode(line, ',');
    strVect.erase(strVect.begin());
    for(auto s : strVect){
        unQuantizedFeatures.push_back(stold(s));
    }
    in_file.close();
    return unQuantizedFeatures;
}

pair<unsigned long, vector<double>> readSampleWithID(string filename, int sample){
    vector<double> unQuantizedFeatures;
    ifstream in_file;
    string line{}, str{};
    vector<string> strVect, strVect1;
    unsigned long userID;
    in_file.open(filename);
    if (!in_file)
    {
        throw "File open error"s; 
    }
    for(int i = -1; i<sample; i++){
        getline(in_file, line);
    }
    strVect = explode(line, ',');
    strVect1 = explode(strVect.at(0), '_');
    str = strVect1.at(0)+strVect1.at(1);
    userID = stoul(str);
    strVect.erase(strVect.begin());
    for(auto s : strVect){
        unQuantizedFeatures.push_back(stold(s));
    }
    in_file.close();
    return make_pair(userID, unQuantizedFeatures);
}






















void writePubKeyinFile(string filename, string partyID, string typeKey, shared_ptr<PublicKey> pubKey){
    ofstream out_file;
    out_file.open(filename, ios::app);

    if (!out_file)
    {
        throw "Error creating file"s;
    }
    auto pk = dynamic_cast<ElGamalPublicKey*>(pubKey.get())->generateSendableData()->toString();
    out_file << setfill(',');
    out_file << setw(1+partyID.size()) << left << partyID;
    out_file << setw(1+typeKey.size()) << left << typeKey;     
    out_file << pk << endl;  
    out_file.close();
}

void writeGPELTinFile(string filename, string partyID, string typeKey, shared_ptr<GroupElement> gpElt){
    ofstream out_file;
    out_file.open(filename, ios::app);

    if (!out_file)
    {
        throw "Error creating file"s;
    }
    out_file << setfill(',');
    out_file << setw(1+partyID.size()) << left << partyID;
    out_file << setw(1+typeKey.size()) << left << typeKey;     
    out_file << gpElt->generateSendableData()->toString() << endl;  
    out_file.close();
}

void writeBigintinFile(string filename, string partyID, string typeKey, biginteger bigint){
    ofstream out_file;
    out_file.open(filename, ios::app);

    if (!out_file)
    {
        throw "Error creating file"s;
    }
    out_file << setfill(',');
    out_file << setw(1+partyID.size()) << left << partyID;
    out_file << setw(1+typeKey.size()) << left << typeKey;     
    out_file << bigint.str() << endl;  
    out_file.close();
}


void writePermutation(string filename, map<int, vector<int>> permutation){
    ofstream out_file;
    out_file.open(filename, ios::app);
    string line, perm;
    size_t lenPer = permutation.size(), lenLine;
    if (!out_file)
    {
        throw "Error creating file"s;
    }
    for (size_t i = 0; i < lenPer ; i++)
    {
        line = to_string(i);
        out_file << setfill(':');
        out_file << setw(1+line.size()) << left << line;
        lenLine = permutation[i].size();
        for(size_t j = 0; j < lenLine ; j++){
            out_file << setfill(',');
            perm = to_string(permutation[i].at(j));
            out_file << setw(1+perm.size()) << left << perm;  
        }           
        out_file << endl;
    }    
    out_file.close();
}

void writeTemplate(string dir, map<int, vector<Component>> userTemplate){
    ofstream out_file;
    string filename = dir+userTemplate[0].at(0).userId.str()+"Template.txt";
    out_file.open(filename, ios::app);
    string posI, posJ, str;
    size_t lenTemp = userTemplate.size(), lenLine;
    if (!out_file)
    {
        throw "Error creating file"s;
    }
    for (size_t i = 0; i < lenTemp ; i++)
    {
        posI = to_string(i);        
        lenLine = userTemplate[i].size();

        for(size_t j = 0; j < lenLine ; j++){
            auto comp = userTemplate[i].at(j);
            posJ = to_string(j);
            out_file << setfill(',');
            out_file << setw(1+posI.size()) << left << posI;
            out_file << setfill('=');
            out_file << setw(1+posJ.size()) << left << posJ;

            out_file << setfill(';');
            str = comp.userId.str();
            out_file << setw(1+str.size()) << left << str;
            str = comp.indexComp.str();
            out_file << setw(1+str.size()) << left << str;
            str = comp.colEnc.get()->generateSendableData()->toString();
            out_file << setw(1+str.size()) << left << str;
            str = comp.scoreEnc.get()->generateSendableData()->toString();
            out_file << setw(1+str.size()) << left << str;  
            str = comp.colEncSig.toString();
            out_file << setw(1+str.size()) << left << str;   
            str = comp.scoreEncSig.toString();
            out_file << setw(1+str.size()) << left << str;    
            out_file << endl;
        }           
        
    }    
    out_file.close();

}

void writeTemplateSH(string dir, map<int, vector<shared_ptr<AsymmetricCiphertext>>> userTemplate){
    ofstream out_file;
    string filename = dir+"Template.txt";
    out_file.open(filename, ios::app);
    string posI, posJ, str;
    size_t lenTemp = userTemplate.size(), lenLine;
    if (!out_file)
    {
        throw "Error creating file"s;
    }
    for (size_t i = 0; i < lenTemp ; i++)
    {
        posI = to_string(i); 
        out_file << setfill('='); 
        out_file << setw(1+posI.size()) << left << posI;   

        lenLine = userTemplate[i].size();

        for(size_t j = 0; j < lenLine ; j++){
            auto comp = userTemplate[i].at(j);
            out_file << setfill(';');
            str = comp.get()->generateSendableData()->toString();
            out_file << setw(1+str.size()) << left << str;    
        }
        out_file << endl;           
        
    }    
    out_file.close();

}

void writeVectCipherinFile(string filename, vector<shared_ptr<AsymmetricCiphertext>> vectCipher){
    ofstream out_file;
    out_file.open(filename, ios::app);
    string str, posI;
    size_t lenCipher = vectCipher.size();
    if (!out_file)
    {
        throw "Error creating file"s;
    }
    for(size_t i = 0; i < lenCipher ; i++){
        posI = to_string(i);
        out_file << setfill('=');
        out_file << setw(1+posI.size()) << left << posI;
        str = vectCipher.at(i).get()->generateSendableData()->toString();
        out_file << setw(1+str.size()) << left << str;   
        out_file << endl;
    }        
    out_file.close();

}

void writeCSV(string filename, std::chrono::time_point<std::chrono::system_clock> start, bool endMeasure){
    auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    string str = to_string(elapsed_ms);
    ofstream out_file;
    out_file.open(filename, ios::app);
    if (!out_file)
    {
        throw "Error creating file"s;
    }
    out_file << setfill(',');
    out_file << setw(1+str.size()) << left << str;
    if(endMeasure == true){
        out_file << endl;
    }       
    out_file.close();

}

void writeCSVNew(std::ofstream& out_file, std::chrono::time_point<std::chrono::system_clock> start, bool endMeasure){
    auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    string str = to_string(elapsed_ms);
    out_file << setfill(',');
    out_file << setw(1+str.size()) << left << str;
    if(endMeasure == true){
        out_file << endl;
        out_file.close();
    }     
}


void writeResult(string filename, int resMatch){
    ofstream out_file;
    out_file.open(filename, ios::app);
    if (!out_file)
    {
        throw "Error creating file"s;
    }
    out_file << to_string(resMatch) << endl;  
    out_file.close();
}
