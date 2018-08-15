// Encryption.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstdio>
#include <Windows.h>
#include <sstream>
#include <sys/stat.h>
using namespace std;

#include "sha256.h"
using namespace custom;

#include "C:\cryptopp562\osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "C:\cryptopp562\cryptlib.h"
using CryptoPP::Exception;

#include "C:\cryptopp562\hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "C:\cryptopp562\filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformation;
using CryptoPP::StreamTransformationFilter;

#include "C:\cryptopp562\aes.h"
using CryptoPP::AES;

#include "C:\cryptopp562\modes.h"
using CryptoPP::CFB_Mode;

#include "C:\cryptopp562\secblock.h"
using CryptoPP::SecByteBlock;

#include "C:\cryptopp562\pwdbased.h"
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include "C:\cryptopp562\sha.h";
using CryptoPP::SHA256;

int getOperationSelection();
void encryptFile();
void decryptFile();
string getDeviceId();
string getUserId();
string getRegionalKey();
void setInputFileStream(ifstream &stream, string message, string &filename);
void setOutputFileStream(ofstream &stream, string message);
string hashStrings(string string1, string string2);
string encrypt(string plainString, byte* iv, SecByteBlock key);
string decrypt(string cipherString, byte* iv, SecByteBlock key);

int main()
{
	// Prompt for encryption or decryption
	int selection = getOperationSelection();

	while (selection == 1 || selection == 2)
	{
		if (selection == 1)
		{
			encryptFile();
		}
		else if (selection == 2)
		{
			decryptFile();
		}

		selection = getOperationSelection();
	}
	
	return 0;
}

int getOperationSelection()
{
	int selection = 0;

	cout << "Please select an option:" << endl;
	cout << "1. Encrypt file." << endl;
	cout << "2. Decrypt file." << endl;
	cout << endl << "Press any other key to exit." << endl;

	cin >> selection;

	return selection;
}

void encryptFile()
{
	string filename;

	// get file streams
	ifstream plainFile;
	setInputFileStream(plainFile, "Filename to be encrypted: ", filename);

	ofstream cipherFile;
	setOutputFileStream(cipherFile, "Filename after encryption: ");

	// get device id
	string deviceId = getDeviceId();
	
	// get user id
	string userId = getUserId();

	// Load plaintext file into memory.
	string plainString((istreambuf_iterator<char>(plainFile)), istreambuf_iterator<char>());
	
	
	// Break plaintext into frames
	int frameBytes = 16;
	const int maxFrames = 100;
	int frameCount = plainString.length() / frameBytes + 1;

	if (frameCount > maxFrames)
	{
		frameBytes = plainString.length() / maxFrames;
		frameCount = plainString.length() / frameBytes + 1;
	}

	string* frameStrings;
	frameStrings = new string[frameCount];

	// Load all frames except for last.
	for (int x = 0; x < frameCount - 1; x++)
	{
		frameStrings[x] = plainString.substr(x * frameBytes, frameBytes);
	}

	// Load the last (potentially partial) frame
	frameStrings[frameCount - 1] = plainString.substr((frameCount - 1) * frameBytes);
	
	// Create random IV
	AutoSeededRandomPool prng;
	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	// Create Key
	unsigned int iterations = 15000;
	string keyString = hashStrings(userId, deviceId);
	char purpose = 0; // unused by Crypto++
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
	kdf.DeriveKey(key.data(), key.size(), purpose, (byte*)keyString.data(), keyString.size(), NULL, 0, iterations);
	
	// Encrypt first frame
	string cipherString = encrypt(frameStrings[0], iv, key);

	// Write random IV and first frame to cipher file.
	cipherFile.write((char*)iv, sizeof(iv));
	cipherFile << cipherString;

	// Encrypt and write all additional frames.
	for (int x = 1; x < frameCount; x++)
	{
		// Create the new key
		string newKey = hashStrings(cipherString, keyString);
		key.CleanNew(AES::DEFAULT_KEYLENGTH);
		kdf.DeriveKey(key.data(), key.size(), purpose, (byte*)newKey.data(), newKey.size(), NULL, 0, iterations);
		
		// Encrypt the frame with the new key
		cipherString = encrypt(frameStrings[x], iv, key);
		
		// Write encrypted string to cipher file.
		cipherFile << cipherString;
	}

	// Close filestreams.
	plainFile.close();
	cipherFile.close();
}

string encrypt(string plainString, byte* iv, SecByteBlock key)
{
	string cipherString;
	string encoded;

	CFB_Mode<AES>::Encryption e;
	e.SetKeyWithIV(key, key.size(), iv);

	// Encrypt plaintext into ciphertext.
	StringSource ss1(plainString, true,
		new StreamTransformationFilter(e,
			new StringSink(cipherString)
			)
		);

	return cipherString;
}

void decryptFile()
{
	string filename;

	// get file streams
	ifstream cipherFile;
	setInputFileStream(cipherFile, "Filename to be decrypted: ", filename);

	ofstream plainFile;
	setOutputFileStream(plainFile, "Filename after decryption: ");

	// get device id
	string deviceId = getDeviceId();

	// Get userId
	string userId = getUserId();
	
	// Read random IV and ciphertext from file.
	byte iv[AES::BLOCKSIZE];
	//string cipherString;
	string cipherString((istreambuf_iterator<char>(cipherFile)), istreambuf_iterator<char>());
	string ivString;

	ivString = cipherString.substr(0, sizeof(iv));
	cipherString = cipherString.substr(sizeof(iv), cipherString.length());

	for (int x = 0; x < ivString.length(); x++)
	{
		iv[x] = ivString[x];
	}
	
	// Break ciphertext into frames
	int frameBytes = 16;
	const int maxFrames = 100;
	int frameCount = cipherString.length() / frameBytes + 1;

	if (frameCount > maxFrames)
	{
		frameBytes = cipherString.length() / maxFrames;
		frameCount = cipherString.length() / frameBytes + 1;
	}
	string* frameStrings;
	frameStrings = new string[frameCount];

	// Load all frames except for last.
	for (int x = 0; x < frameCount - 1; x++)
	{
		frameStrings[x] = cipherString.substr(x * frameBytes, frameBytes);
	}

	// Load the last (potentially partial) frame
	frameStrings[frameCount - 1] = cipherString.substr((frameCount - 1) * frameBytes);
	
	// Create Key
	unsigned int iterations = 15000;
	string keyString = hashStrings(userId, deviceId);
	char purpose = 0; // unused by Crypto++
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
	kdf.DeriveKey(key.data(), key.size(), purpose, (byte*)keyString.data(), keyString.size(), NULL, 0, iterations);
	
	// Decrypt first frame
	string plainString = decrypt(frameStrings[0], iv, key);

	// Write first frame to plain file.
	plainFile << plainString;

	
	// Decrypt and write all additional frames.
	for (int x = 1; x < frameCount; x++)
	{
		// Create the new key
		string newKey = hashStrings(frameStrings[x - 1], keyString);
		key.CleanNew(AES::DEFAULT_KEYLENGTH);
		kdf.DeriveKey(key.data(), key.size(), purpose, (byte*)newKey.data(), newKey.size(), NULL, 0, iterations);

		// Decrypt the frame with the new key
		plainString = decrypt(frameStrings[x], iv, key);

		// Write encrypted string to cipher file.
		plainFile << plainString;
	}

	// Close filestreams.
	cipherFile.close();
	plainFile.close();
}

string decrypt(string cipherString, byte* iv, SecByteBlock key)
{
	string decoded;
	string plainString;

	CFB_Mode<AES>::Decryption d;
	d.SetKeyWithIV(key, key.size(), iv);

	// Decrypt from binary to plaintext.
	StringSource ss3(cipherString, true,
		new StreamTransformationFilter(d,
			new StringSink(plainString)
			)
		);

	return plainString;
}

string hashStrings(string string1, string string2)
{
	custom::SHA256 sha256;

	return sha256(string1 + string2);
}

void setOutputFileStream(ofstream &stream, string message)
{
	string filename;

	cout << message;
	cin >> filename;

	stream.open(filename, ios::binary);
}

void setInputFileStream(ifstream &inputStream, string message, string &filename)
{
	cout << message;
	cin >> filename;

	inputStream.open(filename, ios::binary);

	while (!inputStream)
	{
		cout << "That file does not exist." << endl;
		cout << message;
		cin >> filename;

		inputStream.open(filename);
	}
}

string getRegionalKey()
{
	string regionalKey;

	cout << "Enter Regional Key: ";
	cin >> regionalKey;

	return regionalKey;
}

string getUserId()
{
	string userId;

	cout << "Enter User ID: ";
	cin >> userId;

	custom::SHA256 sha256;
	return sha256(userId);
}

string getDeviceId()
{
	DWORD disk_serialINT;
	if (!GetVolumeInformationA(NULL, NULL, NULL, &disk_serialINT, NULL, NULL, NULL, NULL))
	{
		std::cout << "Failed: " << GetLastError() << std::endl;
		abort();
	}

	disk_serialINT;

	stringstream deviceHex;
	deviceHex << hex << disk_serialINT;

	custom::SHA256 sha256;
	return sha256(deviceHex.str());
}

