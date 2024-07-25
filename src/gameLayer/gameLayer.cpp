/*
Bootleg AES-256 CBC File Encrypter
https://github.com/Northstrix/Bootleg-AES-256-CBC-File-Encrypter
Used libraries:
https://github.com/kokke/tiny-AES-c
https://github.com/meemknight/glui
https://github.com/ulwanski/sha512
*/
#include "gameLayer.h"
#include "gl2d/gl2d.h"
#include "platformInput.h"
#include "imgui.h"
#include <iostream>
#include <sstream>
#include "glui/glui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "aes.h"
#include "sha512.h"
#include <windows.h>
#include <wincrypt.h>

gl2d::Renderer2D renderer;

gl2d::Font font;
gl2d::Texture texture;
gl2d::Texture terrariaTexture;
gl2d::Texture logoTexture;
gl2d::Texture tick;
glui::RendererUi ui;

bool initGame()
{
	renderer.create();
	//font.createFromFile(RESOURCES_PATH "roboto_black.ttf");
	//font.createFromFile(RESOURCES_PATH "font/ANDYB.TTF");
	font.createFromFile("C:\\Windows\\Fonts\\segoeui.ttf"); // Load the Windows font

	return true;
}

void print_hex(const char* label, const uint8_t* data, size_t length) {
    printf("%s:\n", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void test_encrypt_cbc() {
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t out[] = { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
                      0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
                      0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
                      0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b };

    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);

    print_hex("Expected output", out, 64);
    print_hex("Actual output", in, 64);

    if (0 == memcmp((char*) out, (char*) in, 64)) {
        printf("SUCCESS!\n");
    } else {
        printf("FAILURE!\n");
    }
}

static int test_encrypt_ecb()
{
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t out[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };

    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    
    struct AES_ctx ctx;

    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, in);

    print_hex("Expected output", out, 16);
    print_hex("Actual output", in, 16);

    if (0 == memcmp((char*) out, (char*) in, 16)) {
        printf("SUCCESS!\n");
	return(0);
    } else {
        printf("FAILURE!\n");
	return(1);
    }
}

void showError(const char *message) {
    MessageBox(NULL, message, "Error", MB_ICONERROR | MB_OK);
}

// Function to pad the data using PKCS7
void pkcs7_pad(const uint8_t *input, size_t input_len, uint8_t *output, size_t block_size) {
    // Calculate the number of padding bytes needed
    size_t padding_len = block_size - (input_len % block_size);
    
    // If the input length is already a multiple of the block size,
    // add a full block of padding
    if (padding_len == 0) {
        padding_len = block_size;
    }
    
    // Copy the input data to the output buffer
    memcpy(output, input, input_len);
    
    // Add the padding bytes
    for (size_t i = input_len; i < input_len + padding_len; i++) {
        output[i] = (uint8_t)padding_len;
    }
}

void write_byte_array_to_file(const char *fpath, const unsigned char *file_arr, size_t fileSize, bool overwrite, bool add_encr_ext) {
    char *new_path = NULL;
    FILE *file = NULL;
    size_t path_len;
    const char *extension;
    if (add_encr_ext == true){
        extension = ".encr";
        path_len = strlen(fpath) + strlen(extension);
    }
    else{
        path_len = strlen(fpath);
    }

    // Check if the new path would exceed the maximum length
    if (path_len >= 1006) {
        showError("File path exceeds 1000 characters");
        return;
    }

    // Allocate memory for the new file path
    new_path = (char*)malloc(path_len + 1);  // Explicit cast to char*
    if (new_path == NULL) {
        showError("Memory allocation failed");
        return;
    }

    // Construct the new file path
    strcpy(new_path, fpath);
    if (add_encr_ext == true)
        strcat(new_path, extension);

    // Open the file in the appropriate mode
    file = fopen(new_path, overwrite ? "wb" : "ab");
    if (file == NULL) {
        showError("Failed to create encrypted file");
        free(new_path);
        return;
    }

    // Write the data to the file
    size_t written = fwrite(file_arr, 1, fileSize, file);
    if (written != fileSize) {
        showError("Failed to write encrypted data to the .encr file.");
        fclose(file);
        free(new_path);
        return;
    }

    // Close the file and free allocated memory
    fclose(file);
    free(new_path);
}

void write_encrypted_iv_to_file(const char *fpath, const uint8_t *encryption_key, uint8_t *iv){
    //print_hex("IV", iv, 16);
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, encryption_key);
    AES_ECB_encrypt(&ctx, iv);
    //print_hex("Encrypted IV", iv, 16);
    write_byte_array_to_file(fpath, iv, 16, false, true);
}

void encrypt_file_with_aes256_cbc(const char *fpath, const uint8_t *encryption_key, uint8_t *iv, const unsigned char *file_arr, size_t fileSize){
    //printf("\n\nEncrypting file: %s\n\n", fpath);
    //print_hex("Encryption Key | User Input -> SHA512 -> Result", encryption_key, 32);
    //print_hex("IV", iv, sizeof(iv));
    //print_hex("Hex plaintext", file_arr, fileSize);
    size_t padded_len = fileSize;

    // Calculate the padded length
    if (fileSize % AES_BLOCKLEN == 0) {
        padded_len += AES_BLOCKLEN;
    } else {
        padded_len += AES_BLOCKLEN - (fileSize % AES_BLOCKLEN);
    }

    // Allocate memory for the padded data
    uint8_t *padded_data_array = (uint8_t*)malloc(padded_len);
    if (padded_data_array == NULL) {
        showError("Failed to allocate memory for padded data.");
        return;
    }

    // Pad the data
    pkcs7_pad((const uint8_t*)file_arr, fileSize, padded_data_array, AES_BLOCKLEN);

    //print_hex("Padded plaintext", padded_data_array, padded_len);
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, encryption_key, iv);
    AES_CBC_encrypt_buffer(&ctx, padded_data_array, padded_len);
    //print_hex("Encrypted Data", padded_data_array, padded_len);
    write_byte_array_to_file(fpath, padded_data_array, padded_len, true, true);
    write_encrypted_iv_to_file(fpath, encryption_key, iv);
    // Free the allocated memory
    free(padded_data_array);
    MessageBox(NULL, "Encryption process has ended!", "Information", MB_ICONINFORMATION | MB_OK);
}

// Function to encrypt the file content
void prepare_data_for_encr(const char *fpath, const unsigned char *file_arr, size_t fileSize, const char *encr_key) {
    //printf("Encrypting file with key:%s\n", encr_key);
    std::string read_data_std_str(reinterpret_cast<const char*>(encr_key), strlen(encr_key));
    // Calculate SHA512 and get the hex string
    std::string hashHex = sha512(read_data_std_str); // Produces 128-char hex string
    uint8_t encryption_key[32]; // Allocate a buffer for the hash (e.g., SHA-512 produces 64 bytes)
    for (size_t i = 0; i < 32; ++i) {
        std::string byteString = hashHex.substr(i * 2, 2); // Get two characters
        encryption_key[i] = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16)); // Convert to
    }

    HCRYPTPROV hCryptProv;

    uint8_t iv[16]; // Buffer to hold random bytes

    // Acquire a cryptographic provider context
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        // Generate random bytes
        if (CryptGenRandom(hCryptProv, sizeof(iv), iv)) {
            encrypt_file_with_aes256_cbc(fpath, encryption_key, iv, file_arr, fileSize);
        } else {
            showError("Error during CryptGenRandom.");
        }
        // Release the cryptographic provider context
        CryptReleaseContext(hCryptProv, 0);
    } else {
        showError("Error acquiring cryptographic context.");
    }
}

std::string processPath(const char *fpath) {
    // Convert const char* to std::string
    std::string path(fpath);

    // Check if the path ends with ".encr"
    const std::string extension = ".encr";
    if (path.length() >= extension.length() &&
        path.compare(path.length() - extension.length(), extension.length(), extension) == 0) {
        // Remove the ".encr" extension
        path.erase(path.length() - extension.length());
    }

    return path;
}

size_t pkcs7_padding_consumed(const uint8_t data[16]) {
    // Check if the last 16 bytes are all 0x10
    bool allTen = true;

    for (size_t i = 0; i < 16; i++) {
        if (data[i] != 0x10) {
            allTen = false;
            break;
        }
    }

    if (allTen) {
        return 16; // Return 16 if all are 0x10
    }

    // Get the last byte, which indicates the number of padding bytes
    uint8_t paddingValue = data[15];

    // Validate the padding value
    if (paddingValue < 1 || paddingValue > 16) {
        return 0; // Invalid padding
    }

    // Check if the last paddingValue bytes are all equal to paddingValue
    for (size_t i = 1; i <= paddingValue; i++) {
        if (data[16 - i] != paddingValue) {
            return 0; // Invalid padding
        }
    }

    // If all checks pass, return the number of padding bytes consumed
    return paddingValue; 
}

bool areArraysEqual(const uint8_t* array1, const uint8_t* array2) {
    if (array1 == NULL || array2 == NULL) {
        // If either array is NULL, they are not considered equal
        return false;
    }

    for (size_t i = 0; i < 64; i++) {
        if (array1[i] != array2[i]) {
            return false;
        }
    }

    return true;
}

void continue_file_decryption(const char *fpath, const unsigned char *file_arr, size_t fileSize, const uint8_t *decryption_key, const uint8_t *iv) {
    std::string filepath = processPath(fpath);

    // Allocate a new uint8_t array to hold the copied data
    uint8_t *array_for_data = static_cast<uint8_t *>(malloc(fileSize));
    if (array_for_data == nullptr) {
        // Handle memory allocation failure
        showError("Failed to allocate memory for file decryption.");
        return;
    }

    // Copy the data from file_arr to array_for_data
    memcpy(array_for_data, file_arr, fileSize);

    // Initialize AES context
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, decryption_key, iv);

    // Decrypt the copied data
    AES_CBC_decrypt_buffer(&ctx, array_for_data, fileSize);
    //print_hex("Decrypted data (padded)", array_for_data, fileSize);

    uint8_t last_block[16];
    size_t startIndex = fileSize - 16;

    // Copy the last 16 elements into the last_block array
    for (size_t i = 0; i < 16; i++) {
        last_block[i] = array_for_data[startIndex + i];
    }

    size_t padding_size = pkcs7_padding_consumed(last_block);

    if(padding_size == 0){
        // Show a inv_padding_message box with Yes and No buttons
        int msgBoxID = MessageBox(
            NULL,
            "Invalid padding.\nThis may be due to an incorrect decr. key or a corrupted file.\nPlease check your decryption key and try again.\nWould you like to keep the file?",
            "Decryption error",
            MB_ICONERROR | MB_YESNO
        );
        // Check the user's response
        if (msgBoxID == IDYES) {
            write_byte_array_to_file((filepath + ".inv_pad").c_str(), array_for_data, fileSize, true, false);
        } else {
        }
    }
    else{
        fileSize -= padding_size;
        //print_hex("Decrypted data", array_for_data, fileSize);
        uint8_t extr_hash[64];
        fileSize -= 64;
        for (size_t i = 0; i < 64; i++) {
            extr_hash[i] = array_for_data[fileSize + i];
        }
        //print_hex("Plaintext", array_for_data, fileSize);
        //print_hex("Decrypted hash", extr_hash, 64);
        std::string decrypted_data_string(reinterpret_cast<const char*>(array_for_data), fileSize);

        // Calculate SHA512 and get the hex string
        std::string calculated_hashHex = sha512(decrypted_data_string); // Produces 128-char hex string
        //printf("sha512sum: %s\n\n", calculated_hashHex.c_str()); // Print the calculated_hash for verification

        // Fill the calculated_hash array from the hex string
        uint8_t calculated_hash[64]; // Allocate a buffer for the calculated_hash (e.g., SHA-512 produces 64 bytes)
        for (size_t i = 0; i < 64; ++i) {
            std::string byteString = calculated_hashHex.substr(i * 2, 2); // Get two characters
            calculated_hash[i] = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16)); // Convert to byte
        }
        //print_hex("Calculated hash", calculated_hash, 64);
        if (areArraysEqual(extr_hash, calculated_hash)){ // Correct padding + correct hash
            write_byte_array_to_file(filepath.c_str(), array_for_data, fileSize, true, false);
            char message[1050]; // Adjust size as needed
            snprintf(message, sizeof(message), "The file \"%s\" decrypted successfully!", fpath);
            MessageBox(NULL, message, "Success", MB_OK | MB_ICONINFORMATION);
        }
        else{
            int msgBoxID = MessageBox(
                NULL,
                "Integrity Verification Failed!\nThis may be due to an incorrect decr. key or a corrupted file.\nPlease check your decryption key and try again.\nWould you like to keep the file?",
                "Decryption error",
                MB_ICONERROR | MB_YESNO
            );
            // Check the user's response
            if (msgBoxID == IDYES) {
                write_byte_array_to_file((filepath + ".failed_integrity_ver").c_str(), array_for_data, fileSize, true, false);
            } else {
            }
        }
    }
    // Free the allocated memory
    free(array_for_data);
}

// Function to decrypt the file content
void begin_file_decryption(const char *fpath, const unsigned char *file_arr, size_t fileSize, const char *decr_key) {
    //printf("Decrypting file with key:%s\n", decr_key);
    // Print hex content
    //print_hex("Ciphertext (HEX)", file_arr, fileSize);
    uint8_t iv[16];
    size_t startIndex = fileSize - 16;

    // Copy the last 16 elements into the iv array
    for (size_t i = 0; i < 16; i++) {
        iv[i] = (uint8_t)file_arr[startIndex + i];
    }

    //print_hex("Encrypted IV", iv, 16);

    std::string read_data_std_str(reinterpret_cast<const char*>(decr_key), strlen(decr_key));
    // Calculate SHA512 and get the hex string
    std::string hashHex = sha512(read_data_std_str); // Produces 128-char hex string
    uint8_t decryption_key[32]; // Allocate a buffer for the hash (e.g., SHA-512 produces 64 bytes)
    for (size_t i = 0; i < 32; ++i) {
        std::string byteString = hashHex.substr(i * 2, 2); // Get two characters
        decryption_key[i] = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16)); // Convert to
    }

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, decryption_key);
    AES_ECB_decrypt(&ctx, iv);
    //print_hex("Decrypted IV", iv, 16);

    fileSize -= 16; // Don't count IV
    continue_file_decryption(fpath, file_arr, fileSize, decryption_key, iv);
}

void read_file(const char *fpath, bool encrypt_file_flag, const char *crypt_key) {
    FILE *file = fopen(fpath, "rb"); // Open the file in binary mode
    if (!file) {
        // File does not exist, show an error
        char errorMessage[1024];
        snprintf(errorMessage, sizeof(errorMessage), "File at \"%s\" doesn't exist.", fpath);
        showError(errorMessage);
        return;
    }

    // Seek to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    unsigned long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET); // Reset to the beginning of the file

    // Allocate memory for the file content
    size_t allocationSize = fileSize;
    if (encrypt_file_flag) {
        allocationSize += 64; // Allocate additional bytes if encrypting
    }

    unsigned char *buffer = (unsigned char *)malloc(allocationSize);
    if (!buffer) {
        fclose(file);
        showError("Memory allocation failed.");
        return;
    }

    // Read the file content into the buffer
    size_t bytesRead = fread(buffer, 1, fileSize, file);
    //printf("Bytes read: %zu\n", bytesRead); // Use %zu for size_t
    fclose(file); // Close the file after reading

    if (encrypt_file_flag) {
        // Copy the content of the buffer into std::string
        std::string read_data_std_str(reinterpret_cast<const char*>(buffer), bytesRead);

        // Calculate SHA512 and get the hex string
        std::string hashHex = sha512(read_data_std_str); // Produces 128-char hex string
        //printf("sha512sum: %s\n\n", hashHex.c_str()); // Print the hash for verification

        // Fill the hash array from the hex string
        unsigned char hash[64]; // Allocate a buffer for the hash (e.g., SHA-512 produces 64 bytes)
        for (size_t i = 0; i < 64; ++i) {
            std::string byteString = hashHex.substr(i * 2, 2); // Get two characters
            hash[i] = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16)); // Convert to byte
        }

        // Copy original buffer and append hash
        memcpy(buffer + bytesRead, hash, sizeof(hash)); // Append hash to the buffer

        // Encrypt the combined buffer
        prepare_data_for_encr(fpath, buffer, bytesRead + sizeof(hash), crypt_key);
    } else {
        // Decrypt the file
        begin_file_decryption(fpath, buffer, bytesRead, crypt_key);
    }

    // Free the allocated memory
    free(buffer);
}

void render1()
{
 ui.Begin(101);

    glm::vec4 customTransform = {};
    bool clicked = 0;
    bool hovered = 0;
    static char crypt_key[200];
    static char fpath[1000];
    ui.Text("Bootleg AES-256 CBC File Encrypter", Colors_Gray);
    ui.BeginMenu("Encrypt File", Colors_Transparent, texture);
    ui.Text("Encrypt File", gl2d::Color4f(50.0/255.0, 92.0/255.0, 127.0/255.0, 1.0));

    // Input for the encryption/decryption key
    ui.InputText("Key: ", crypt_key, sizeof(crypt_key));
    ui.InputText("Path: ", fpath, sizeof(fpath));

    // Encrypt option
    if (ui.Button("Encrypt", Colors_Transparent, texture)) {
        // Check if the file path is empty
        if (fpath[0] == '\0') {
            showError("Path to the file can't be empty");
        } else {
            char message[1050]; // 1000 for fpath + 50 for additional text
            snprintf(message, sizeof(message), "Are you sure you want to encrypt the \"%s\" file?", fpath);

            // Show a message box with Yes and No buttons
            int msgBoxID = MessageBox(
                NULL,
                message,
                "Confirmation",
                MB_ICONQUESTION | MB_YESNO
            );

            // Check the user's response
            if (msgBoxID == IDYES) {
                read_file(fpath, true, crypt_key); // Pass true for encryption
            } else {
                MessageBox(NULL, "Operation was cancelled by user.", "Info", MB_OK);
            }
        }
    }

    // Clean option
    if (ui.Button("Clean", Colors_Transparent, texture)) {
        for (int i = 0; i < 200; i++) {
            crypt_key[i] = 0;
        }
        for (int i = 0; i < 1000; i++) {
            fpath[i] = 0;
        }
    }

    // Escape key handling
    if (platform::isKeyReleased(platform::Button::Escape)) {
        printf("Esc is pressed!\n");
        for (int i = 0; i < 200; i++) {
            crypt_key[i] = 0;
        }
    }

    ui.Text("Press \"Esc\" to return", gl2d::Color4f(164.0/255.0, 71.0/255.0, 32.0/255.0, 1.0));
    ui.EndMenu();
    ui.BeginMenu("Decrypt File", Colors_Transparent, texture);
    ui.Text("Decrypt File", gl2d::Color4f(50.0/255.0, 92.0/255.0, 127.0/255.0, 1.0));

    // Input for the encryption/decryption key
    ui.InputText("Key: ", crypt_key, sizeof(crypt_key));
    ui.InputText("Path: ", fpath, sizeof(fpath));

    // Decrypt option
    if (ui.Button("Decrypt", Colors_Transparent, texture)) {
        // Check if the file path is empty
        if (fpath[0] == '\0') {
            showError("Path to the file can't be empty");
        } else {
            // Create the confirmation message
            char message[1050]; // Adjust size as needed
            snprintf(message, sizeof(message), "Are you sure you want to decrypt the \"%s\" file?", fpath);

            // Show a message box with Yes and No buttons
            int msgBoxID = MessageBox(
                NULL,
                message,
                "Confirmation",
                MB_ICONQUESTION | MB_YESNO
            );

            // Check the user's response
            if (msgBoxID == IDYES) {
                //printf("%s %s\n", "Decryption key:", crypt_key);
                read_file(fpath, false, crypt_key); // Pass false for decryption
            } else {
                MessageBox(NULL, "Operation was cancelled by user.", "Info", MB_OK);
            }
        }
    }

    // Clean option
    if (ui.Button("Clean", Colors_Transparent, texture)) {
        for (int i = 0; i < 200; i++) {
            crypt_key[i] = 0;
        }
        for (int i = 0; i < 1000; i++) {
            fpath[i] = 0;
        }
    }

    // Escape key handling
    if (platform::isKeyReleased(platform::Button::Escape)) {
        printf("Esc is pressed!\n");
        for (int i = 0; i < 200; i++) {
            crypt_key[i] = 0;
        }
    }

    ui.Text("Press \"Esc\" to return", gl2d::Color4f(164.0/255.0, 71.0/255.0, 32.0/255.0, 1.0));
    ui.EndMenu();
    if(ui.Button("Quit", Colors_Transparent, {})){
        for (int i = 0; i < 200; i++) {
            crypt_key[i] = 0;
        }
        bool all_zeroes = true;

        for (int i = 0; i < 200; i++) {
            if (crypt_key[i] != 0) {
                all_zeroes = false;
                break;
            }
        }

        if (all_zeroes) {
            exit(0);
        } else {
            exit(1);
        }
    }
    ui.Text("github.com/Northstrix", gl2d::Color4f(136.0/255.0, 204.0/255.0, 136.0/255.0, 1.0));
    ui.End();
}

bool gameLogic(float deltaTime)
{
#pragma region init stuff
	int w = 0; int h = 0;
	w= platform::getWindowSizeX();
	h = platform::getWindowSizeY();
	
	renderer.updateWindowMetrics(w, h);
	renderer.clearScreen(gl2d::Color4f(2.0/255.0, 77.0/255.0, 49.0/255.0, 1.0));
#pragma endregion

	//ImGui::ShowDemoWindow();

	render1();

#pragma region set finishing stuff

	ui.renderFrame(renderer, font, platform::getRelMousePosition(),
		platform::isLMousePressed(), platform::isLMouseHeld(), platform::isLMouseReleased(),
		platform::isKeyReleased(platform::Button::Escape), platform::getTypedInput(), deltaTime);

	renderer.flush();

	return true;
#pragma endregion

}

void closeGame()
{

}
