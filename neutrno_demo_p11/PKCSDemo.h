#ifndef PKCSDEMO_H
#define PKCSDEMO_H

const CK_ULONG MODULUS_BIT_LENGTH = 2048;

class CPKCSDemo
{
public:
	CPKCSDemo(void);
	~CPKCSDemo();
	void ShowMsg(char *strInfo);
	void ShowErr(char *strInfo, CK_RV rv);
	void ClearMsg(void);
	CK_RV Connect();
	CK_RV Login();
	CK_RV Keypairgen(char* key_label);
	void Sign(char * key_label , char * hash_input);
	void Verify(char * key_label , char * signature  , char * original_hash);
	void Clearinfo();
	void Encrypt();
	void Decrypt();
	void Destroy();

	CK_SLOT_ID_PTR m_pSlotList;
	CK_VOID_PTR m_pApplication;
	CK_SESSION_HANDLE m_hSession;
	CK_OBJECT_HANDLE m_hPubKey;
	CK_OBJECT_HANDLE m_hPriKey;
	bool m_bKeyGen;
	CK_BYTE m_pSignature[MODULUS_BIT_LENGTH];
	CK_BYTE_PTR m_pbCipherBuffer;
	CK_ULONG m_ulSignatureLen;
	CK_ULONG m_ulCipherLen;

};

#endif
