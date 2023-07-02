#pragma once
#pragma comment(lib, "crypt32") //These 2 are only needed for building openssl on Windows
#pragma comment(lib, "ws2_32.lib")
#include <iostream> //cout
#include <string> //strings
#include <fstream> //file io
#include <vector> //Vector arrays
#include <stdlib.h>	//openssl b64 decoding function
#include <openssl/evp.h> //high level evp handler
#include <openssl/err.h> //openssl error outputs
#include <map> //for entropy
#include <thread> //multi-threading
#include <algorithm>	//For filling c array with value
#include <future> //multi-threading
#include <tuple> //for results to gather data together


using namespace std; //I'm sorry future me

//Return how long the wordlist is
unsigned int wordlist_length(string wordlist_name);

//Decode base64 to unsigned char with openssl functions
unsigned char* decode64(const char* input);

//Helper struct to pack the parameters for the AES_decrypt function below in a neater fashion
struct AES_params_struct{
    unsigned char* ciphertext;
    int ciphertext_len;
    unsigned char* key;
    unsigned char* iv;
    unsigned char* plaintext;
    int mode;
    int chaining_mode;
    int pkcs_padding;
};

//Actual AES decrypt, mode defines key size and sets the plaintext input in the struct to the result
int AES_decrypt(struct AES_params_struct);

//For entropy
float log2a(float number);

//Actual entropy function
float entropy_calc(unsigned char* data, int data_length);

//KDF derive the key according to corresponding mode given. Return pointer to 32 byte array containing derived key
void kdf(int kdf_mode, int kdf_padding, string current_key, unsigned char* key);

//Helper struct to pack the parameters for the AESdecodeList function below in a neater manner
//We also set defaults / watcher values here
struct thread_params_struct {
    unsigned char* enc_data;    //Payload ciphertext bytes
    int enc_data_length;    //Payload length
    int mode = 1337;   //128, 192, 256 bit key 1/2/3
    string wordlist_name = "PLACEHOLDER_WORDLIST";
    unsigned int index_start;   //Where each instance of threads should start from the wordlist
    unsigned int index_span;    //How far should they check in that wordlist from the index_start
    int kdf_mode = 1;  //We default to the site's KDF of 1. 1 = pad with values, 2 = repeat key till length desired
    int kdf_padding = 0;    //The padding byte to use with the KDF 1 mode. Default of 00 to match the site
    int chaining_mode = 0; //Chaining mode, 0 = CBC, 1 = ECB. Default of 0 to match site
    int pkcs_padding = 1;   //Set to 0 to disable auto-checking of pkcs7 padding on the plaintext. Default 1 to match site
    unsigned char* iv;
    int iv_copy_flag = 0;   //We set this flag is c is passed to -i, tells us to copy the key to use as the IV instead of an actual IV
};


//AES Decrypt list with given bounds for multithreading
void AESdecodeList(promise<tuple<string, string, double>> p, struct thread_params_struct);