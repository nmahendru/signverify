#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "include/cryptoki_ext.h"
#include "PKCSDemo.h"

using namespace std;

int main(int argc, char ** argv )
{
	if (argc != 3){
		cout << "Usage: pkcsdemo <key handle to use> <hash of the file to be signed>" << endl ;
		exit(-1);
	}
	char * key_handle = argv[1];
	char * hash = argv[2];
	CK_RV rv;

	//cout<<"[]==================================================[]"<<endl;
	//cout<<" |             	PKCS#11 Demo 		           |"<<endl;
	//cout<<"[]==================================================[]"<<endl;

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
/*	cout<<"Now,generating key pair... ..."<<endl;
	rv = demo.Keypairgen();
	if(CKR_OK != rv)
	{
		C_Finalize(NULL_PTR);
		return FALSE;
	}*/
	bool sign = true;
	bool canSing = false;
	bool canDecrypt = false;
			demo.Verify();
	//while(sign)
	/*{
		cout<<"1: Sign,";
		if(canSing) cout<<"2: Verify,";
		cout<<"3: Encrypt,";
		if(canDecrypt) cout<<"4: Decrypt,";
		cout<<"5: Exit"<<endl;
		string s;
		cin>>s;
		if((!cin) || (s.length() > 1))
		{
			cout<<"1-5 only"<<endl;
			cin.clear();
			cin.get();
			continue;
		}
		switch(s[0])
		{*/
			//case '1':
		//demo.Sign(argv[1], argv[2]);

	/*			break;
			case '2':
				if(canSing)
				{
					demo.Verify();
				}else
				{
					cout<<"need \"Sign\" first!"<<endl;
				}
				break;
			case '3':
				demo.Encrypt();
				canDecrypt = true;
				break;
			case '4':
				if(canDecrypt)
				{
					demo.Decrypt();
				}else
				{
					cout<<"need \"Encrypt\" first!" <<endl;
				}
				break;
			case '5':
				cout<<"Exit"<<endl;
				demo.Destroy();
				sign = false;
				break;
			default:
				cout<<"1-5 only"<<endl;
				break;
		}*/
	//}
	rv = C_Finalize(NULL_PTR);
	if(rv == CKR_OK)
		demo.m_hSession = NULL;
	return FALSE;
}
