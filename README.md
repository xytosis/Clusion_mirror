# The Clusion Library

Clusion is an easy to use software library for searchable symmetric encryption
(SSE). Its goal is to provide modular implementations of various
state-of-the-art SSE schemes. Clusion includes constructions that handle
single, disjunctive, conjunctive and (arbitrary) boolean keyword search.  All
the implemented schemes have *optimal* asymptotic search complexity in the
worst-case.  

Clusion is provided as-is under the *GNU General Public License v3 (GPLv3)*. 


## Implementation

*Indexing.* The indexer takes as input a folder that can contain pdf files,
Micorosft files such .doc, .ppt, media files such as pictures and videos as
well as raw text files such .html and .txt. The indexing step outputs two
lookup tables. The first associates keywords to document filenames while the
second associates filenames to keywords. For the indexing, we use Lucene to
tokenize the keywords and get rid of noisy words.  For this phase, Apache
Lucene, PDFBox and POI are required. For our data structures, we use Google
Guava.

*Cryptographic primitives.* All the implementations make use of the Bouncy
Castle library. The code is modular and all cryptographic primitives are
gathered in the `CryptoPrimitives.java` file.  The file contains AES-CTR,
HMAC_SHA256/512, AES-CMAC, key generation based on PBE PKCS1 and random string
generation based on SecureRandom.  In addition, it also contains an
implementation of the HCB1 online cipher from \[[BBKN07][BBKN07]\]. 



The following SSE schemes are implemented:

+ **2Lev**:  a static and I/O-efficient SSE scheme \[[CJJJKRS14][CJJJKRS14]]\. 

+ **BIEX-2Lev**: a  worst-case optimal boolean SSE scheme \[KM16\].
  This implementation makes use of 2Lev as a building block.  The
disjunctive-only IEX-2Lev construction from \[KM16\] is a special case
of IEX^B-2Lev where the number of disjunctions is set to 1 in the Token
algorithm.

+ **ZMF**: a compact single-keyword SSE scheme 
  (with linear search complexity) \[KM16\]. The construction is
inspired by  the Z-IDX construction \[[Goh03][Goh03]\] but handles
variable-sized collections of Bloom filters called *Matryoshka filters*. ZMF
also makes a non-standard use of online ciphers.  Here, we implemented the
HCBC1 construction from  \[[BBKN07][BBKN07]\] but would like to replace this
with the more efficient COPE scheme from \[[ABLMTY13][ABLMTY13]\]. 

+ **BIEX-ZMF**: a compact worst-case optimal boolean SSE scheme. Like our
  IEX^B-2Lev implementation, the purely disjunctive variant IEX-ZMF is a special case with the number of disjunctions set to 1. 

+ **IEX-2Lev-Amazon**: a distributed implementation of text indexing based on MapReduce/Hadoop
on [Amazon AWS](https://aws.amazon.com/fr/). 

+ We also plan to share our Client-Server implementation for 2Lev, IEX^B-2Lev, IEX^B-ZMF once finalized. 

## Build Instructions

+ Install Java (1.7 or above)
+ Install Maven (3.3.9 or above)
+ Download/Git clone Clusion
+ Run below commands to build the jar

	`cd Clusion`
	
	`mvn clean install`
	
	`cd target`
	
	`ls Clusion-1.0-SNAPSHOT-jar-with-dependencies.jar`
	
+ If the above file exists, build was successful and contains all dependencies

## Quick Test

For a quick test, create folder and store some input files, needed jars and test classes are already created

+ export Java classpath

	run `export CLASSPATH=$CLASSPATH:/home/xxx/Clusion/target:/home/xxx/Clusion/target/test-classes`
	
	Ensure the directory paths are correct in the above
	
+ to test 2Lev 

	run `java org.crypto.sse.TestLocal2Lev`
	
+ to test 2Lev (response-hiding)

	run `java org.crypto.sse.TestLocalRH2Lev`	

+ to test ZMF 

	run `java org.crypto.sse.TestLocalZMF`	
	
+ to test IEX-2Lev 

	run `java org.crypto.sse.TestLocalIEX2Lev`
	
+ to test IEX-2Lev (response-hiding)

	run `java org.crypto.sse.TestLocalIEXRH2Lev`
	
+ to test IEX-ZMF 

	run `java org.crypto.sse.TestLocalIEXZMF`
	
+ to test IEX-2Lev on Amazon 

	run `java org.crypto.sse.IEX2LevAMAZON`


## Documentation

Clusion currently does not have any documentation. The best way to learn how to
use the library is to read through the source of the test code:

+ `org.crypto.sse.TestLocal2Lev.java`
+ `org.crypto.sse.TestLocalRH2Lev.java`
+ `org.crypto.sse.TestLocalZMF.java`
+ `org.crypto.sse.TestLocalIEX2Lev.java`
+ `org.crypto.sse.TestLocalIEXRH2Lev.java`
+ `org.crypto.sse.TestLocalIEXZMF.java`

## Requirements
Clusion is written in Java.

Below are Dependencies added via Maven (3.3.9 or above) , need not be downloaded manually

+ Bouncy Castle					https://www.bouncycastle.org/

+ Apache Lucene					https://lucene.apache.org/core/

+ Apache PDFBox					https://pdfbox.apache.org/

+ Apache POI					https://poi.apache.org/

+ Google Guava					https://poi.apache.org/

+ SizeOF (needed to calculate object size in Java)	http://sizeof.sourceforge.net/

+ [Hadoop-2.7.1](http://hadoop.apache.org/releases.htm) was used for our
  distributed implementation of the IEX-2Lev setup algorithm. Earlier releases
 of Hadoop may work as well but were not tested 

Clusion was tested with Java version `1.7.0_75`.

## AlchemyVision Integration and Remote Server

Clusion is integrated with the AlchemyVision API in order to extract keywords from images. It is also augmented so that we can run the server and client on different machines and be able to transfer the EDS and encrypted files back and forth between the two. We also augment Clusion so that the server and client can persist their states so that upon a shutdown or restart, they do not have to run the setup step again.

### Usage

This section describe running the code via the command line. We first compile everything with `mvn package`. We then need to use the jar file WITHOUT all the dependencies added, and manually link to the dependenccies that maven downloaded. We cannot use the fat jar because the BouncyCastle dependency relies on it being signed, and packaging destroys the original signature.

Thus, running the client should be like
```
java -cp "Clusion-1.0-SNAPSHOT.jar:MVN_DEPENDENCY_PATH/*" org.crypto.remote.ImageClient HOST PORT
```
where `MVN_DEPENDENCY_PATH` is the directory in which maven downloads dependency jars, `HOST` is the host and `PORT` is the port that the server is running on.

Similarly, running the server should look like
```
java -cp "Clusion-1.0-SNAPSHOT.jar:MVN_DEPENDENCY_PATH/*" org.crypto.remote.ImageServer PORT
```

Once the server and client have started running, they will prompt the user to input a series of options for the type of session to run. It will ask the user if they want to start a new session or load in an existing session (every new session will be saved once it has started running), and what type of encryption scheme the user wants.

When the options have been decided, if the user went with loading a previous scheme, the client will immediately start the query phase. If the user went with starting a new scheme, the client will take in a directory of files and index and encrypt them and send them to the server, and then will start the query phase.

All the queries are saved in a folder in the current directory, and on the server side, all the encrypted images are also saved in a folder in the current directory.

## References

1. \[[CJJJKRS14](https://eprint.iacr.org/2014/853.pdf)\]:  *Dynamic Searchable Encryption in Very-Large Databases: Data Structures and Implementation* by D. Cash, J. Jaeger, S. Jarecki, C. Jutla, H. Krawczyk, M. Rosu, M. Steiner.

2. \[KM16\]:  *Boolean Searchable Symmetric Encryption with -Case Sub-Linear Complexity* by S. Kamara and T. Moataz. Available upon request. 

3. \[[Goh03](https://eprint.iacr.org/2003/216.pdf)\]: *Secure Indexes* by E. Goh. 

4. \[[ABLMTY13](https://eprint.iacr.org/2013/790.pdf)\]: *Parallelizable and
   Authenticated Online Ciphers* by E. Andreeva, A.  Bogdanov, A. Luykx, B.
Mennink, E. Tischhauser, and K. Yasuda. . 

5. \[[BBKN07](https://cseweb.ucsd.edu/~mihir/papers/olc.pdf)\]:  *On-Line
   Ciphers and the Hash-CBC Constructions* by M. Bellare, A. Boldyreva, L.
Knudsen and C. Namprempre.


[CJJJKRS14]: https://eprint.iacr.org/2014/853.pdf
[Goh03]: https://eprint.iacr.org/2003/216.pdf
[ABLMTY13]: https://eprint.iacr.org/2013/790.pdf
[BBKN07]: https://cseweb.ucsd.edu/~mihir/papers/olc.pdf

# TODO
1. Make the encrypted data structure encrypted in the server. Whenever the client wants to search, they have to use the
same password (make sure to save the salt and stuff)

2. Clusion has many static variables. Make sure they will get serialized.

3. Next, work on IEX2lev and IEXRH2lev (boolean queries)

4. Make this work on remote server