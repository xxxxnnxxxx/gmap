
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <snmp.h>

#include <WinSock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "arp.h"


/*
the following code are from https://www.codeproject.com/Articles/22483/Edit-Add-Remove-Modify-ARP-Tables

thanks.
*/

#pragma	comment(lib, "snmpapi.lib")
#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "ws2_32.lib")
//-----------------------------------------------------------------------
//	From MSDN Help: http://msdn2.microsoft.com/en-us/library/aa378018(VS.85).aspx
//
//	The Microsoft SNMP service calls the SnmpExtensionInit function to initialize 
//	the SNMP extension agent DLL. This function is an element of the SNMP Extension Agent API.
//
//	BOOL SnmpExtensionInit(
//	  DWORD dwUptimeReference,                    // see NOTE below
//	  HANDLE *phSubagentTrapEvent,                // trap event handle
//	  AsnObjectIdentifier *pFirstSupportedRegion  // first MIB subtree
//	);
//-----------------------------------------------------------------------
typedef BOOL(WINAPI* PFNSNMPEXTENSIONINIT)	(DWORD, HANDLE*, AsnObjectIdentifier*);

//-----------------------------------------------------------------------
//	From MSDN Help: http://msdn2.microsoft.com/en-us/library/aa378021.aspx
//
//	The Microsoft SNMP service calls the SnmpExtensionQuery function to resolve SNMP 
//	requests that contain variables within one or more of the SNMP extension agent's 
//	registered MIB subtrees. This function is an element of the SNMP Extension Agent API. 
//
//
//	BOOL SnmpExtensionQuery(
//	  BYTE bPduType,                  // SNMPv1 PDU request type
//	  SnmpVarBindList *pVarBindList,  // pointer to variable bindings
//	  AsnInteger32 *pErrorStatus,     // pointer to SNMPv1 error status
//	  AsnInteger32 *pErrorIndex       // pointer to the error index
//	);
//-----------------------------------------------------------------------
typedef BOOL(WINAPI* PFNSNMPEXTENSIONQUERY)(BYTE, SnmpVarBindList*, AsnInteger32*, AsnInteger32*);


HMODULE					hMIBLibrary;			// Handle for library: inetmib1.dll
PFNSNMPEXTENSIONINIT	pfnSnmpExtensionInit;	// Pointer to function: SnmpExtensionInit
PFNSNMPEXTENSIONQUERY	pfnSnmpExtensionQuery;	// Pointer to function: SnmpExtensionQuery


BOOL  WINAPI InitSNMPLib() {
	BOOL bInitialized = FALSE;
	// Load dynamic library: inetmib1.dll
	hMIBLibrary = LoadLibrary(TEXT("inetmib1.dll"));

	// If library loaded, get addresses of (SnmpExtensionInit, pfnSnmpExtensionQuery) functions
	if (hMIBLibrary) {
		pfnSnmpExtensionInit = (PFNSNMPEXTENSIONINIT)GetProcAddress(hMIBLibrary, "SnmpExtensionInit");
		pfnSnmpExtensionQuery = (PFNSNMPEXTENSIONQUERY)GetProcAddress(hMIBLibrary, "SnmpExtensionQuery");

		// If success get addresses and initialize SNMP, bInitialized = true
		if (pfnSnmpExtensionInit && pfnSnmpExtensionQuery) {
			HANDLE				hPollForTrapEvent;
			AsnObjectIdentifier	aoiSupportedView;

			bInitialized = pfnSnmpExtensionInit(0, &hPollForTrapEvent, &aoiSupportedView);
		}
	}
	else
	{
		// If fail to get addresses, bInitialized = false
		bInitialized = FALSE;

	}

	return bInitialized;
}

int WINAPI GetEntries(ArpTable* pTable, int TableLength, int AdapterIndex) {

	SnmpVarBindList		SVBList[3];
	SnmpVarBind			SVBVars[3];
	UINT				OID[3][10];
	AsnInteger32		aiErrorStatus[3], aiErrorIndex[3];

	int s = sizeof(OID[0]);
	AsnObjectIdentifier	AsnOID0 = { sizeof(OID[0]) / sizeof(UINT), OID[0] };
	AsnObjectIdentifier	AsnOID1 = { sizeof(OID[1]) / sizeof(UINT), OID[1] };
	AsnObjectIdentifier	AsnOID2 = { sizeof(OID[2]) / sizeof(UINT), OID[2] };
	INT_PTR		pIPAddress;
	INT_PTR		pMACAddress;
	int					iEntries;


	//-----------------------------------------------------------------------
	//	Fill array of 3 OIDs
	//	
	//	OID[0]	:	"1.3.6.1.2.1.4.22.1.1", ipNetToMediaIfIndex
	//				The interface on which this entry's equivalence is effective
	//
	//	OID[1]	:	"1.3.6.1.2.1.4.22.1.2", ipNetToMediaPhysAddress
	//				The media-dependent 'physical' address
	//
	//	OID[2]	:	"1.3.6.1.2.1.4.22.1.4", ipNetToMediaType
	//				Entry type: 1:Other, 2:Invalid(Remove), 3:Dynamic, 4:Static
	//
	for (int count = 0; count < 3; count++)
	{
		OID[count][0] = 1;
		OID[count][1] = 3;
		OID[count][2] = 6;
		OID[count][3] = 1;
		OID[count][4] = 2;
		OID[count][5] = 1;
		OID[count][6] = 4;
		OID[count][7] = 22;
		OID[count][8] = 1;

		switch (count)
		{
		case 0:
			// Adapter interface
			OID[count][9] = 1;
			break;

		case 1:
			// MAC address
			OID[count][9] = 2;
			break;

		case 2:
			// Entry Type
			OID[count][9] = 4;
			break;
		}
	}

	ZeroMemory(pTable, sizeof(ArpTable) * TableLength);

	SVBList[0].len = 1;
	SVBList[0].list = &SVBVars[0];
	SnmpUtilOidCpy(&SVBVars[0].name, &AsnOID0);

	SVBList[1].len = 1;
	SVBList[1].list = &SVBVars[1];
	SnmpUtilOidCpy(&SVBVars[1].name, &AsnOID1);

	SVBList[2].len = 1;
	SVBList[2].list = &SVBVars[2];
	SnmpUtilOidCpy(&SVBVars[2].name, &AsnOID2);

	iEntries = 0;
	do
	{
		aiErrorStatus[0] = 0;
		aiErrorIndex[0] = 0;
		aiErrorStatus[1] = 0;
		aiErrorIndex[1] = 0;
		aiErrorStatus[2] = 0;
		aiErrorIndex[2] = 0;

		// Query information of 3 OIDs
		if (pfnSnmpExtensionQuery(SNMP_PDU_GETNEXT, &SVBList[0], &aiErrorStatus[0], &aiErrorIndex[0]))
			if (pfnSnmpExtensionQuery(SNMP_PDU_GETNEXT, &SVBList[1], &aiErrorStatus[1], &aiErrorIndex[1]))
				if (pfnSnmpExtensionQuery(SNMP_PDU_GETNEXT, &SVBList[2], &aiErrorStatus[2], &aiErrorIndex[2]))
					if (aiErrorStatus[0] == SNMP_ERRORSTATUS_NOERROR &&
						aiErrorStatus[1] == SNMP_ERRORSTATUS_NOERROR &&
						aiErrorStatus[2] == SNMP_ERRORSTATUS_NOERROR) // Check for error
					{
						//-----------------------------------------------------------------------
						// From MSDN Help: http://msdn2.microsoft.com/en-us/library/aa378021.aspx
						// 
						// If the extension agent cannot resolve the variable bindings on a Get Next request, 
						// it must change the name field of the SnmpVarBind structure to the value of the object 
						// identifier immediately following that of the currently supported MIB subtree view. 
						// For example, if the extension agent supports view ".1.3.6.1.4.1.77.1", a Get Next 
						// request on ".1.3.6.1.4.1.77.1.5.1" would result in a modified name field of ".1.3.6.1.4.1.77.2". 
						// This signals the SNMP service to continue the attempt to resolve the variable bindings 
						// with other extension agents
						//-----------------------------------------------------------------------

						if (SnmpUtilOidNCmp(&SVBVars[0].name, &AsnOID0, AsnOID0.idLength))
							break;
						if (SnmpUtilOidNCmp(&SVBVars[1].name, &AsnOID1, AsnOID1.idLength))
							break;
						if (SnmpUtilOidNCmp(&SVBVars[2].name, &AsnOID2, AsnOID2.idLength))
							break;

						// Verify selected Adapter interface
						if (AdapterIndex == SVBList[0].list->value.asnValue.number)
						{
							// pIPAddress get pointer ro IP Address
							pIPAddress = (INT_PTR)SVBList[1].list->name.ids;
							pTable[iEntries].IPAddress[0] = *(unsigned char*)(pIPAddress + 44);
							pTable[iEntries].IPAddress[1] = *(unsigned char*)(pIPAddress + 48);
							pTable[iEntries].IPAddress[2] = *(unsigned char*)(pIPAddress + 52);
							pTable[iEntries].IPAddress[3] = *(unsigned char*)(pIPAddress + 56);

							// pIPAddress get pointer ro MAC Address
							pMACAddress = (INT_PTR)SVBList[1].list->value.asnValue.string.stream;
							if (pMACAddress)
							{
								pTable[iEntries].MACAddress[0] = *(unsigned char*)(pMACAddress + 0);
								pTable[iEntries].MACAddress[1] = *(unsigned char*)(pMACAddress + 1);
								pTable[iEntries].MACAddress[2] = *(unsigned char*)(pMACAddress + 2);
								pTable[iEntries].MACAddress[3] = *(unsigned char*)(pMACAddress + 3);
								pTable[iEntries].MACAddress[4] = *(unsigned char*)(pMACAddress + 4);
								pTable[iEntries].MACAddress[5] = *(unsigned char*)(pMACAddress + 5);
							}

							// Entry Type
							pTable[iEntries].Type = (unsigned long)SVBList[2].list->value.asnValue.number;

							// Type must be one of (1, 2, 3, 4)
							if (pTable[iEntries].Type >= 1 && pTable[iEntries].Type <= 4)
								iEntries++;		// Move to next array position
						}
					}
					else
						break;	// If error exit do-while
	} while (iEntries < TableLength);

	// Frees the memory allocated for the specified object identifiers
	SnmpUtilOidFree(&SVBVars[2].name);
	SnmpUtilOidFree(&SVBVars[1].name);
	SnmpUtilOidFree(&SVBVars[0].name);

	return iEntries;	// Return number of Entries
}