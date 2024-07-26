# MUSES: Efficient Multi-User Searchable Encrypted Database
![x86](https://github.com/vt-asaplab/MUSES/blob/main/MUSES/emp_lib/workflows/x86/badge.svg)
![arm](https://github.com/vt-asaplab/MUSES/blob/main/MUSES/emp_lib/workflows/arm/badge.svg)

<img src=" https://github.com/vt-asaplab/MUSES/blob/main/MUSES/emp_lib/workflows/uae/badges.png" width="100" height="100">

This is our full implementation for our [MUSES paper](https://eprint.iacr.org/2023/720).

**WARNING**: This is an academic proof-of-concept prototype and has not received careful code review. This implementation is NOT ready for production use.

# Required Libraries

1. [NTL](http://www.shoup.net/ntl/download.html)

2. [ZeroMQ](https://github.com/zeromq/cppzmq/releases/tag/v4.8.1)

3. [Secp256k1](https://github.com/bitcoin-core/secp256k1/tree/423b6d19d373f1224fd671a982584d7e7900bc93)

4. [EMP-Toolkit](https://github.com/emp-toolkit/emp-agmpc)

You can run the script file **auto_setup.sh** to automatically install the required libraries and build source code. 
```
sudo ./auto_setup.sh
```

# Build & Compile

Go to the folder **Server** and folder **Client** then execute:
``` 
make clean
make
```
This is going to create executable files *Server* in **Server** folder and *Client* in **Client** folder.

## Testing

1. Launch server:
```
cd Server
./Server <Server_ID> <Server_Port> [-b <Bloom_Filter_Size>] [-d <Number_of_Documents>] [-w <Number_of_Writers>] [-ns <Search_Result_Size>]
```

For example, we launch server 1:
```
./Server 1 12345
```
Then launch server 2:
```
./Server 2 12345
```
The default parameters: Bloom_Filter_Size is 1120, Number_of_Documents is 1024, Number_of_Writers is 1 and Search_Result_Size is 255. 

2. Launch client:
```
cd Client
./Client [-b <Bloom_Filter_Size>] [-d <Number_of_Documents>] [-w <Number_of_Writers>] [-ns <Search_Result_Size>] 
```

For example: 
```
./Client
```

**NOTE**: The configuration (including Bloom_Filter_Size, Number_of_Documents, Number_of_Writers and Search_Result_Size) need to be consistent when starting servers and client. For instance *(Bloom_Filter_Size = 2000, Number_of_Documents = 32768, Number_of_Writers = 25, Search_Result_Size = 1023)*:
```
./Server 1 12345 -b 2000 -d 32768 -w 25 -ns 1024
./Server 2 12345 -b 2000 -d 32768 -w 25 -ns 1024
./Client -b 2000 -d 32768 -w 25 -ns 1024
```

You can start server/client applications in any order.

## Configuring Number of Servers:
Change the constant defined at line 11 ``const int nP          = 2;`` in file **config.hpp** and recompile both Server and Client.

## Configuring Number of Threads:
Change the constant defined at line 9 ``const int MAX_THREADS = 8;`` in file **config.hpp** and recompile both Server and Client.

## Configuring IP Addresses:
To run experiments with EC2 instances, we need to change the IP loopback ```127.0.0.1``` to the IP addresses of EC2 servers as follows. 

1. Server: modify servers' IP address from line 13 to line 18 in file **emp_lib/emp_agmpc/cmpc_config.h** and recompile Server.
```
const static char *IP[] = {""
                          , "127.0.0.1"
                          , "127.0.0.1"
                          , "127.0.0.1"
                          , "127.0.0.1"
                          , "127.0.0.1"
                          , "127.0.0.1"}; 
```


2. Client: modify servers' IP addresses at line 786 ``string ip_addresses[] = {"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"};`` in file **Client/Client.cpp** and recompile Client.

## Configuring Number of Test Execution:
By default, keyword search, document update and permission revocation operations are executed one time. We can increase the number of operations to evaluate their average execution time as follows: 

1. Server: file **Server/Server.cpp**

Line 29 ```int n_secret_key_update_times = 1;``` is to change the number of permission revocations.\
Line 80 ```int n_document_update_times = 1;``` is to change the number of document updates.\
Line 181 ```int n_keyword_search_times = 1;``` is to change the number of keyword search.

2. Client: file **Client/Client.cpp**

Line 74 ```int n_secret_key_update_times = 1;``` is to change the number of permission revocations.\
Line 255 ```int n_document_update_times = 1;``` is to change the number of document updates.\
Line 402 ```int n_keyword_search_times = 1;``` is to change the number of keyword search.

Then recompile both Server and Client. 

**Note**: The configuration need to be kept consistent between Client and Server. 

## Citing

If the code is found useful, we would be appreciated if our paper can be cited with the following bibtex format 

```
@inproceedings {le2024muses,
author = {Le, Tung and Behnia, Rouzbeh and Guajardo, Jorge and  Hoang, Thang},
title = {{MUSES}: Efficient {M}ulti-User {S}earchable {E}ncrypted {D}atabase},
booktitle = {33rd USENIX Security Symposium (USENIX Security 24)},
year = {2024},
address = {Philadelphia, PA},
publisher = {USENIX Association},
month = aug,
}
```

# Further Information
For any inquiries, bugs, and assistance on building and running the code, please contact me at [tungle@vt.edu](mailto:tungle@vt.edu?Subject=[MUSES]%20Inquiry).
