#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include "include/cryptoki_ext.h"
#include "PKCSDemo.h"


using namespace std;

int main(void )
{
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
	char  userInput[1024] = {0};
	//cout << "Enter the object label you want to destroy" <<endl;
	//cin >> userInput;

	CK_ATTRIBUTE searchTemplate[] = {
		{CKA_LABEL,		  userInput,    sizeof(userInput)},
	};
	CK_ATTRIBUTE searchAllTemplate[] ={

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
	cout << "Destroying all the objects on the usb token" << endl;
	for (int  i = 0 ; i < searchResultCount ; i ++){
	rv = C_DestroyObject(demo.m_hSession , searchResults[i]);
	if (rv == CKR_OK){
		cout << "Destroyed object successfully" << endl;
	}
	}
/*
	cout << "the number of objects found are " << searchResultCount << endl ;
	for (int i= 0 ; i < searchResultCount ; i++){
		cout << i << endl;
		 rv = C_GetAttributeValue(demo.m_hSession , searchResults[i] , searchTemplate , 1);
			if (rv != CKR_OK){
				cout << "Can't get the attribute value for index " << i << endl;
				continue ;
			}
		printf( "the label is %s\n",searchTemplate[0].pValue );
	}
*/
	//demo.Destroy();
	rv = C_Finalize(NULL_PTR);
	if(rv == CKR_OK)
		demo.m_hSession = NULL;
	return FALSE;
}
