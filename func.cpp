#include "func.h"

//Get number of wordlist lines
unsigned int wordlist_length(string wordlist_name)
{
    ifstream wordlist_file;
    wordlist_file.open(wordlist_name);
    //File sanity check
    if (!wordlist_file.is_open())
    {
        perror("Error opening wordlist file");
        exit(EXIT_FAILURE);
    }

    //Load line by line
    unsigned int line_count = 0;
    string line;
    while (getline(wordlist_file, line))
    {
        line_count++;
    }

    wordlist_file.close();

    return line_count;
}

//Decode base64 to unsigned char with openssl functions
unsigned char* decode64(const char* input) {
    unsigned int length = strlen(input);
    const auto pl = 3 * length / 4; //may allocate a few extra unused bytes depending on padding
    auto output = reinterpret_cast<unsigned char*>(calloc(pl + 1, 1));
    const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char*>(input), length);
    if (pl != ol) { std::cerr << "Whoops, decode predicted " << pl << " but we got " << ol << "\n"; }
    return output;
}

//OpenSSL error handler - debug only
void handleErrors(void)
{
    //ERR_print_errors_fp(stderr);
    //std::cout << "Error encountered\n";
    //abort();
}

//Decrypt AES into provided plaintext. mode 1,2,3 == 128, 192, 256
//Return plaintext length
int AES_decrypt(struct AES_params_struct AES_params)
{
    int len;
    int plaintext_len;

    //Make cipher context
    EVP_CIPHER_CTX* ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    //Enable or disable OpenSSL's built in PKCS7 padding verification
    if (AES_params.pkcs_padding == 0)
    {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    //Initialise relevant decryption mode, have to hardcode it like this due to seperate functions for each use-case
    //Use CBC
    if (AES_params.chaining_mode == 0)
    {
        if (AES_params.mode == 1)
        {
            unsigned char keyn[16] = { 0 };
            memcpy(keyn, AES_params.key, 16);

            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyn, AES_params.iv))
                handleErrors();
        }

        if (AES_params.mode == 2)
        {
            unsigned char keyn[24] = { 0 };
            memcpy(keyn, AES_params.key, 24);

            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, keyn, AES_params.iv))
                handleErrors();
        }

        if (AES_params.mode == 3)
        {
            unsigned char keyn[32] = { 0 };
            memcpy(keyn, AES_params.key, 32);

            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keyn, AES_params.iv))
                handleErrors();
        }
    }

    //Use ECB
    else if (AES_params.chaining_mode == 1)
    {
        if (AES_params.mode == 1)
        {
            unsigned char keyn[16] = { 0 };
            memcpy(keyn, AES_params.key, 16);

            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, keyn, NULL))
                handleErrors();
        }

        if (AES_params.mode == 2)
        {
            unsigned char keyn[24] = { 0 };
            memcpy(keyn, AES_params.key, 24);

            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, keyn, NULL))
                handleErrors();
        }

        if (AES_params.mode == 3)
        {
            unsigned char keyn[32] = { 0 };
            memcpy(keyn, AES_params.key, 32);

            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, keyn, NULL))
                handleErrors();
        }


    }

    //Input ciphertext and do inital decryption round, writing to plaintext
    //Note that OpenSSL by default checks for the correct padding so we don't need to
    //EVP_CIPHER_CTX_set_padding(ctx, 0); //If we wanted to disable PKCS7 padding do it here
    if (1 != EVP_DecryptUpdate(ctx, AES_params.plaintext, &len, AES_params.ciphertext, AES_params.ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);   //Error if we're here so free the context and return 0 length
        return 0;
    }
    plaintext_len = len;

    //Do final round for the end plaintext
    if (1 != EVP_DecryptFinal_ex(ctx, AES_params.plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);   //Error if we're here so free the context and return 0 length
        return 0;
    }
    plaintext_len += len;

    //Clear the context
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

//For entropy
float log2a(float number)
{
    return log(number) / 0.69314718056; // ( / ln(2) to change log base)
}

//Return entropy of string input
float entropy_calc(unsigned char* data, int data_length)
{
    int frequencies[256] = {0};
    int i = 0;
    while(i < data_length)
    {
        frequencies[*(data + i)] ++;
        i++;
    }

    float numlen = data_length;
    float entropy = 0;
    for (int occur : frequencies)
    {
        if (occur != 0)
        {
            float freq = occur / numlen;
            entropy -= freq * log2a(freq);
        }
    }

    return entropy;
}

//"Derive" the key with the chosen function
void kdf(int kdf_mode, int kdf_padding, string current_key, unsigned char* key)
{
    switch (kdf_mode)
    {
    case 1: //Padded with desired bytes
        fill(key, key + 32, kdf_padding);   //Pad key then copy over

        //Make sure it isn't >32 so we don't overflow
        if (current_key.length() > 32)
        {
            memcpy(key, current_key.c_str(), 32);
        }
        else
        {
            memcpy(key, current_key.c_str(), current_key.length());
        }

        break;

    case 2: //Key is repeated till >=32
        while (current_key.length() < 32 && current_key.length() != 0)
        {
            current_key += current_key;
        }
        memcpy(key, current_key.c_str(), 32);
        break;
    }
}




//Decode given section of wordlist as a worker thread. Returns a tuple of best key and corresponding plaintext with entropy via a promise
void AESdecodeList(promise<tuple<string, string, double>> p, struct thread_params_struct thread_params)
{

    struct AES_params_struct AES_params;  //Will hold all of arguments to AES call later

    //A lot of these can simply be passed directly from the thread params struct
    AES_params.ciphertext = thread_params.enc_data;
    AES_params.ciphertext_len = thread_params.enc_data_length;
    AES_params.ciphertext_len = thread_params.enc_data_length;
    AES_params.mode = thread_params.mode;
    AES_params.chaining_mode = thread_params.chaining_mode;
    AES_params.pkcs_padding = thread_params.pkcs_padding;

    //Set up framework to hold best results and then loop through the wordlist and record them
    double best_entropy = 1e10;
    tuple<string, string, double> results_list = make_tuple("N/A", "N/A", 1e10); // Will hold the final results. Plaintext, entropy and key used

    //Load file
    ifstream wordlist_file;
    wordlist_file.open(thread_params.wordlist_name);
    //File sanity check
    if (!wordlist_file.is_open())
    {
        perror("Error opening wordlist file");
        exit(EXIT_FAILURE);
    }

    string line;
    unsigned int wordlist_index = 0;
    unsigned char* plaintext = new unsigned char[thread_params.enc_data_length](); //() initalises to 0


    while (getline(wordlist_file, line))    //Read wordlist one line at a time instead of all at once to save memory
    {
        //Before we start get to the correct starting position for the thread
        if (wordlist_index < thread_params.index_start)
        {
            wordlist_index++;
            continue;
        }

        //Also check if we're at the end of our span
        if (wordlist_index == thread_params.index_start + thread_params.index_span)
        {
            wordlist_file.close();
            break;
        }

        //Otherwise we're within the wordlist limit so decrypt normally:


        //Derrive the key according to the desired mode
        string current_key = line;
        unsigned char key[32]; //First create the key, we'll initalise it properly later according to the mode
        kdf(thread_params.kdf_mode, thread_params.kdf_padding, current_key, key);

        //Check if we're using the actual IV passed or are just copying the key to use for the IV
        if (thread_params.iv_copy_flag == 1)
        {
            memcpy(thread_params.iv, key, 16);
        }

        //Now we've derrived/mucked around with these, we can set them to the struct
        AES_params.key = key;
        AES_params.iv = thread_params.iv;


        //Do the actual decryption
        int decryptedtext_len;
        memset(plaintext, 0, thread_params.enc_data_length);

        //Now we've derrived/mucked around with these, we can set them to the struct
        AES_params.key = key;
        AES_params.iv = thread_params.iv;
        AES_params.plaintext = plaintext;

        decryptedtext_len = AES_decrypt(AES_params);  //Sets plaintext variable with result

        //Check if the result was valid
        if (decryptedtext_len != 0) //If the decrypt was sucessful
        {
            //Calculate entropy
            float current_entropy = entropy_calc(plaintext, thread_params.enc_data_length);

            //If this is the best result yet then keep track of it and se it as the new goal
            if (current_entropy < best_entropy)
            {
                best_entropy = current_entropy;
                string plaintext_string(plaintext, plaintext + thread_params.enc_data_length); //Convert to string for ease-of-use. Think this is vestigial now, but doesn't hurt perf
                results_list = make_tuple(current_key, plaintext_string, current_entropy);
            }
        }

        wordlist_index++;
    }

    delete[] plaintext;    //Clean up allocated plaintext
    p.set_value(results_list);   //What we actually return via the promise
}
