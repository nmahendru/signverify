#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <iomanip>
#include "include/cryptoki_ext.h"
#include "PKCSDemo.h"

using namespace std;


int main(int argc, char ** argv )
{
	if (argc != 3){
		cout << "Usage: extractpub <key handle to use> <public key file name>" << endl ;
		exit(-1);
	}
	char * key_label = argv[1];
	char * pubKeyFile = argv[2];
	CK_RV rv;


	rv = C_Initialize(NULL_PTR);
	if(CKR_OK != rv)
	{
		cout<<"Can not load PKCS#11 lib\n"<<endl;
		C_Finalize(NULL_PTR);
		return FALSE;
	}
	CPKCSDemo demo;
	rv = demo.Connect();
	if(CKR_OK != rv)
	{
		C_Finalize(NULL_PTR);
		return FALSE;
	}
	rv = demo.Login();
	if(CKR_OK != rv)
	{
		C_Finalize(NULL_PTR);
		return FALSE;
	}

	char * privateKeyLabel = (char *)malloc(strlen(key_label) + 3 + 1) ;
	strcpy(privateKeyLabel , key_label);
	strcpy(privateKeyLabel + strlen(key_label), "PUB");
	cout << "keyLabel being searched is " << key_label << endl ;
	CK_ATTRIBUTE searchAllTemplate[] = {
		{CKA_LABEL,		  privateKeyLabel,    sizeof(key_label)},
	};
	CK_OBJECT_HANDLE_PTR searchResults = ( CK_OBJECT_HANDLE_PTR ) malloc(sizeof(CK_OBJECT_HANDLE) * 10);
	CK_ULONG searchResultCount = 0;
	rv = C_FindObjectsInit(demo.m_hSession , searchAllTemplate , /*sizeof(searchTemplate) / sizeof(CK_ATTRIBUTE)*/ 0);
	if(rv != CKR_OK)
		cout << "C_FindObjectsInit failed " << hex << setfill('0') << setw(10) << rv << endl ;
	rv = C_FindObjects(demo.m_hSession , searchResults , 10 ,  &searchResultCount);
	if(rv != CKR_OK)
		cout << "C_FindObjects failed " << hex << setfill('0') << setw(10) << rv << endl ;
	rv = C_FindObjectsFinal(demo.m_hSession);
	if(rv != CKR_OK)
		cout << "C_FindObjectsFinal failed " << hex << setfill('0') << setw(10) << rv << endl ;
	cout << "number of keys returned " << searchResultCount << endl ;
	char label[512];
	int label_length;
	unsigned char modulus[4096];
	int mod_length = 4096 ;
	unsigned long modulus_bits = 0;
	unsigned char exponent[4096];
	int exponent_length = 4096 ;
	CK_ATTRIBUTE template1[] = {
		{CKA_LABEL , label , sizeof(label)},
		{CKA_MODULUS, modulus , mod_length},
		{CKA_MODULUS_BITS, &modulus_bits , sizeof(modulus_bits)},
		{CKA_PUBLIC_EXPONENT, exponent, exponent_length },
	};
	int save_index = -1;
	for (int i = 0 ; i < searchResultCount ; i++){
			C_GetAttributeValue(demo.m_hSession, searchResults[i], template1 , 4);
			cout << "label found which going through search results " << label << endl;
			if(strcmp(label,privateKeyLabel) == 0){
				cout << "modulus length " << template1[1].ulValueLen << "  exponent length " << template1[3].ulValueLen  << endl;
				cout << "modulus " <<endl ;
				for (int j = 0 ; j < template1[1].ulValueLen ; j++)	{
				 		printf("%02x",modulus[j]) ;
						if((j+1)%10 == 0) cout << endl;
				}
				cout << endl ;
				cout << "exponent " << endl;
				for (int j = 0 ; j < template1[3].ulValueLen ; j++){
						printf("%02x",exponent[j]);
						}
				cout << endl ;

			}
	 }
	 cout <<endl ;

	rv = C_Finalize(NULL_PTR);
	if(rv == CKR_OK)
		demo.m_hSession = NULL;
	return FALSE;
}
