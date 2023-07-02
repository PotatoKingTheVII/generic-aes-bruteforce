#include "func.h" //All functions

int main(int argc, char* argv[])
{

    //First parse the arguments and set up any warden values to make sure any placeholders have been changed
    struct thread_params_struct thread_params;  //Will hold all of arguments to thread call later

    string ciphertext = "PLACEHOLDER_CT";
    string iv_b64_str = "PLACEHOLDER_IV";
    int thread_count = 1337;
    unsigned char iv[16] = { 49,50,51,52,53,54,55,56,98,48,122,50,51,52,53,110 }; //Set default IV. If  -i is set it'll memcopy over the top of this, always 16 bytes
    thread_params.iv = iv;  //Our param holds the pointer

    //Will point to any custom IV data later from flags
    unsigned char* iv_data;

    //Help message. I'm running out of letters, please help
    string help_text ="\nERROR, correct usage:\n\n"
            "aesbrute.exe -w string -t integer -m integer -c string\n\n"
            "-w : wordlist filename\n"
            "-t : threadcount to use\n"
            "-m : AES mode (1 = 128, 2 = 192, 3 = 256)\n"
            "-c : ciphertext with correct padding\n"
            "-d : digest mode (1 = pad with optional byte by -o, 2 = duplicate password). Default 1\n"
            "-o : padding byte to use with -d 1 (0-255). Default 0\n"
            "-v : Chaining mode, 0 = CBC, 1 = ECB. Default of 0 to match site\n"
            "-p : Verify plaintext with PKCS7 padding. 0 = disabled 1 = enabled. Default is 1\n"
            "-i : Specify what IV to use in CBC mode. Default is site's IV. Pass 'c' to copy key as the IV\n"
            "-h : Show this help\n";


    //Parse the arguments for actual inputs
    if (argc == 1)  //If no flags were given
    {
        cout << help_text;
    }

    //For each argument given
    for (int i = 1; i < argc; ++i)
    {
        string currentArg(argv[i]);
        string tmp_perm_int;

        //If the current argument is actually a flag
        if (currentArg[0] == '-')
        {
            if (i + 1 < argc)   //Check next argument if flag has one, only do this if there's actually another one there
            {
                string currentNextArg(argv[i + 1]);
            }

            switch (currentArg[1])  //Check which flag
            {

            case 't':   //Set threads
                thread_count = (int)*(argv[i + 1]) - 48;  //(Ascii so -48 to get correct range)
                break;
            case 'c':   //Set ciphertext
                ciphertext = string(argv[i + 1]);
                break;

            case 'm':   //Set AES mode
                thread_params.mode = (int)*(argv[i + 1]) - 48;
                break;

            case 'w':   //Set wordlist
                thread_params.wordlist_name = string(argv[i + 1]);
                break;

            case 'd':   //Set KDF mode
                thread_params.kdf_mode = (int)*(argv[i + 1]) - 48;
                break;

            case 'o':   //Set KDF mode 1 padding byte
                thread_params.kdf_padding = stoi(argv[i + 1]);
                break;


            case 'v':   //Set chaining mode
                thread_params.chaining_mode = (int)*(argv[i + 1]) - 48;
                break;

            case 'p':   //Set PKCS7 verification
                thread_params.pkcs_padding = (int)*(argv[i + 1]) - 48;
                break;

            case 'i':   //Set custom IV
                iv_b64_str = string(argv[i + 1]);
                if (iv_b64_str == "c")
                {
                    thread_params.iv_copy_flag = 1;
                }
                else
                {
                    iv_data = decode64(iv_b64_str.c_str());
                    memcpy(iv, iv_data, 16);
                }
                break;

            case 'h':   //Show help
                cout << help_text;
                return 1;
                break;

            default:    //Input error
                cout << help_text;
            }
        }
    }

    //Sanity check to make sure the user actually input all the needed values:
    if (ciphertext == "PLACEHOLDER_CT" || thread_params.mode == 1337 || thread_count == 1337 || thread_params.wordlist_name == "PLACEHOLDER_WORDLIST")
    {
        cout << "\n*Missing arguments*\n";
        return 1;
    }

    //Decode ciphertext - note the carried data will always be 16 byte aligned so we can assume length
    unsigned char* enc_data = decode64(ciphertext.c_str());
    int tmp_length = (ciphertext.length() / 4) * 3;

    thread_params.enc_data = enc_data;
    thread_params.enc_data_length = ((tmp_length + 16 / 2) / 16) * 16;    //Rounds to nearest 16 which will always be rounding up

    //Multi-threading boilerplate
    vector<future<tuple<string, string, double>>> future_results;
    vector<thread> threadPool;

    //Calculate the starting index and span that each thread will have based on how many there are
    unsigned int wordlist_size = wordlist_length(thread_params.wordlist_name);
    unsigned int chunk_size = wordlist_size / thread_count;
    unsigned int chunk_remainder = wordlist_size % thread_count;

    //For each thread we're going to use pass it the correct bounds to use
    for (int i = 0; i < thread_count; i++)
    {
        thread_params.index_start = i * chunk_size;
        thread_params.index_span = chunk_size;

        //But if this is the last thread then add the remainder to it
        if (i == thread_count - 1)
        {
            thread_params.index_span = chunk_size + chunk_remainder;
        }

        //Keep track of the return promises
        promise<tuple<string, string, double>> promise;
        future_results.push_back(promise.get_future());

        //Create the thread, pass it its promise and keep track in the thread pool.
        threadPool.push_back(thread(AESdecodeList, move(promise), thread_params));
    }

    //Actually join all threads
    for (int i = 0; i < thread_count; i++)
    {
        threadPool[i].join();
    }

    //Get results from all threads
    vector<tuple<string, string, double>> ordered_list;
    for (int i = 0; i < thread_count; i++)
    {
        tuple<string, string, double> b = future_results[i].get();
        ordered_list.push_back(b);
    }

    //Sort results list for best entropy to first entry
    sort(ordered_list.begin(), ordered_list.end(),
        [](const auto& i, const auto& j) { return get<2>(i) < get<2>(j); });

    //Output best result
    cout << "\nThe best key was: || " << get<0>(ordered_list[0]) << " || for a plaintext of:\n" << get<1>(ordered_list[0]) << "\n";

    return 0;
}