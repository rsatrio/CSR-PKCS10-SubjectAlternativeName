# Generate CSR 

A simple example of generating CSR programatically. This project was tested with Java 8.

## Features
- CSR with Subject Alternative Name containing RFC 4683 (Subject Identification Method)
- You can easily use this example to integrate with private key from HSM (Hardware Security Module). Just change the signing process to use HSM


## Build
- Use mvn package to build the module into jar file
> mvn clean package

- Put the resulting jar in your classpath
- Add these dependencies in your pom.xml:
<dependency>
   <groupId>org.bouncycastle</groupId>
   <artifactId>bcpkix-jdk15on</artifactId>
   <version>1.60</version>
  </dependency>
  <dependency>
   <groupId>org.ejbca.cesecore</groupId>
   <artifactId>cesecore-common</artifactId>
   <version>7.0.0.1</version>
  </dependency>
  

## Configuration
N/A

## Feedback
For feedback, please raise issues in the issue section of the repository. Periodically, I will update the example with more real-life use case example. Enjoy!!.

