# Fast and Accurate Likelihood Ratio Based Biometric Verification Secure Against Malicious Adversaries


## Description 
This repository contains the proof-of-concept implementation of two biometric verification protocols provably secure against semi-honest and malicious adversaries [1].
The protocols are based on the homomorphically encrypted log likelihood-ratio (HELR) classifier [2] that supports any biometric modality that can be encoded as a fixed-length real-valued feature vector (e.g. face, fingerprint, dynamic signature, etc.).
The protocols perform the biometric recognition under encryption preventing biometric information (i.e. template, probe and score) from leakage in the presence of semi-honest and malicious adversaries.
The implementation of the ZK-proofs used to achieve security against malicious adversaries are also included in this repository.

## Dependencies

This is a C++ implementation that requires the following libraries:

- [`LIBSCAPI`](https://github.com/cryptobiu/libscapi/blob/master/build_scripts/INSTALL.md)
- [`Boost version 1.71.0`](https://www.boost.org/users/history/version_1_71_0.html)
- [`OpenMP`](https://www.openmp.org/)


## Repository Structure

After installing libscapi in `/home/obre` and boost_1_71_0 in `/home/obre` make sure that the project repository has the following structure.

```bash
	obre
	│
	├── bvsma
	│   ├── data
	│   │   ├── client
	│   │   ├── enrollmentServer
	│   │   ├── server
	│   │   └── **/*.csv
	│   │ 
	│   ├── include
	│   │   └── **/*.hpp
	│   │ 
	│   ├── src
	│   │   └── **/*.cpp
	│   │ 
	│   ├── test
	│   │   ├── Protocols
	│   │   │   ├── Malicious
	│   │   │   │   └── Makefile 
	│   │   │   └── SemiHonest
	│   │   │       └── Makefile
	│   │   │   
	│   │   └── ZK
	│   │       └── Makefile             
	│   │
	│   │ 
	│   ├── .gitignore 
	│   └── README.md
	│
	├── libscapi
	│
	└── boost_1_71_0
```


## Experiments

### Verification Protocol Secure Against Semi-Honest Adversaries

1. Go to `/home/obre/test/Protocols/SemiHonest` and execute the following commands

    ```
    make client
    make server
    ```
2. Open two terminals, one for `client` and another for `server` then execute the commands below (one line for each dataset) and make sure that the client and the server are running on the same phase (enrollment first then verification) using the same dataset.
The elliptic curve P192 can be replaced by P224 or P256 (substitute 192 by either 224 or 256).

    - `client` terminal
    
        `./client <phase> <curve> <n_users+1> <step> <dir/DATASET.csv> <DATASET> <n_features> <n_featLevels>`
        
        - First enrollment phase (`<phase>` = 0)

        ```
        ./client 0 192 501 1 /home/obre/bvsma/data/BMDB.csv BMDB 36 16
        ./client 0 192 501 1 /home/obre/bvsma/data/PUT.csv PUT 49 64
        ./client 0 192 501 1 /home/obre/bvsma/data/FRGC.csv FRGC 94 64
        ```
        - Second verification phase (`<phase>` = 1)

        ```
        ./client 1 192 501 1 /home/obre/bvsma/data/BMDB.csv BMDB 36 16
        ./client 1 192 501 1 /home/obre/bvsma/data/PUT.csv PUT 49 64
        ./client 1 192 501 1 /home/obre/bvsma/data/FRGC.csv FRGC 94 64
        ```

    - `server` terminal
    
        `./server <phase> <curve> <n_users+1> <step> <DATASET> <threshold> <Smax-threshold+1>`
        
        - First enrollment phase (`<phase>` = 0)

        ```
        ./server 0 192 501 1 BMDB 14 86
        ./server 0 192 501 1 PUT -53 136
        ./server 0 192 501 1 FRGC -1 75
        ```
        - Second verification phase (`<phase>` = 1)

        ```
        ./server 1 192 501 1 BMDB 14 86
        ./server 1 192 501 1 PUT -53 136
        ./server 1 192 501 1 FRGC -1 75
        ```

3. Only to clean up and re-build, execute the following then go to 1
    ```
    make clean-data
    make clean
    ``` 
    `make clean-data` will delete all users files (such as keys, encrypted template, etc. ) that are in `data/client` and `data/server`.

### Verification Protocol Secure Against Malicious Adversaries

1. Go to `/home/obre/test/Protocols/Malicious` and execute the following commands

    ```
    make client
    make server
    make enrollmentServer
    ```

2. **Enrollment phase:** Open three terminals, one for `client` one for `server` and one for the `enrollmentServer` then execute the commands below (one line for each dataset) and make sure that the client, the server and the enrollmentServer are using the same dataset.
The elliptic curve P192 can be replaced by P224 or P256 (substitute 192 by either 224 or 256).

    - `client` terminal
    
        `./client <phase> <curve> <n_users+1> <step> <dir/DATASET.csv> <DATASET> <n_features> <n_featLevels>`
        ```
        ./client 0 192 501 1 /home/obre/bvsma/data/BMDB.csv BMDB 36 16
        ./client 0 192 501 1 /home/obre/bvsma/data/PUT.csv PUT 49 64
        ./client 0 192 501 1 /home/obre/bvsma/data/FRGC.csv FRGC 94 64
        ```
    
    - `enrollmentServer` terminal
    
        `./enrollmentServer <curve> <n_users+1> <step> <DATASET> <threshold> <Smax-threshold+1>`
        
        ```
        ./enrollmentServer 192 501 1 14 86 BMDB 
        ./enrollmentServer 192 501 1 -53 136 PUT 
        ./enrollmentServer 192 501 1 -1 75 FRGC 
        ```

    - `server` terminal

        `./server <phase> <curve> <n_users+1> <step> <DATASET>`

        ```
        ./server 0 192 501 1 BMDB
        ./server 0 192 501 1 PUT
        ./server 0 192 501 1 FRGC
        ```



3. **Verification phase:** Open two terminals, one for `client` and another for `server` then execute the commands below (one line for each dataset) and make sure that the client and the server are running on the same phase (enrollment first then verification) using the same dataset. 
The elliptic curve P192 can be replaced by P224 or P256 (substitute 192 by either 224 or 256).

    - `client` terminal
        ```
        ./client 1 192 501 1 /home/obre/bvsma/data/BMDB.csv BMDB 36 16
        ./client 1 192 501 1 /home/obre/bvsma/data/PUT.csv PUT 49 64
        ./client 1 192 501 1 /home/obre/bvsma/data/FRGC.csv FRGC 94 64
        ```
    - `server` terminal

        ```
        ./server 1 192 501 1 BMDB 
        ./server 1 192 501 1 PUT 
        ./server 1 192 501 1 FRGC 
        ```

4. Only to clean up and re-build, execute the following then go to 1
    ```
    make clean-data
    make clean
    ``` 
    `make clean-data` will delete all users files (such as keys, encrypted template, etc. ) that are in `data/client`, `data/server` and `data/enrollmentServer`.

### Adapted ZK-Proofs

1. Go to `/home/obre/test/ZK` and execute the following commands

    ```
    make prover
    make verifier
    ```
    For an optimized version based on OpenMP, execute these commands
    ```
    make proverParallel
    make verifierParallel
    ```
2. Open two terminals, one for `prover` (or `proverParallel`) and another for `verifier` (or `verifierParallel`) then execute the following commands by specifying the elliptic curve P192, P224 or P256 (without P) and the desired ZK-proof either single proofs `{zkPoKBasic, zkPoKSinglePlain, niZKDecZero, niZKBlinded, niZKPartialDec}` or AND-proofs `{zkPoKMultiANDPlain, niZKMultiANDDecZero, niZKMultiANDBlinded, niZKMultiANDPartialDec}`
    - `prover` terminal
        ```
        ./prover 192 zkPoKMultiANDPlain
        ```
    - `verifier` terminal
        ```
        ./verifier 192 zkPoKMultiANDPlain
        ```
3. Only to clean up and re-build, execute the following then go to 1
    ```
    make clean
    ``` 



## References

[[ 1 ]](https://arxiv.org/abs/2101.10631)
[[ 2 ]](https://gitlab.utwente.nl/m7667012/helrclassifier)


## Bibtex Citation

```
@misc{bassit2021biometric,
      title={Biometric Verification Secure Against Malicious Adversaries}, 
      author={Amina Bassit and Florian Hahn and Joep Peeters and Tom Kevenaar and Raymond N. J. Veldhuis and Andreas Peter},
      year={2021},
      eprint={2101.10631},
      archivePrefix={arXiv},
      primaryClass={cs.CR}
}
```

