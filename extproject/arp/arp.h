#ifndef _ARP_H_
#define _ARP_H_

#ifdef __cplusplus
#	ifdef ARP_EXPORTS
#		define ARPAPI extern "C" __declspec(dllexport)
#	else
#		define ARPAPI extern "C"  __declspec(dllimport) 
#	endif
#else
#	ifdef ARP_EXPORTS
#		define ARPAPI  __declspec(dllexport)
#	else
#		define ARPAPI  __declspec(dllimport) 
#	endif
#endif



typedef struct {
	unsigned long	Type;			// Type: 3:Dynamic, 4:Static
	unsigned char	IPAddress[4];	// IP Address
	unsigned char	MACAddress[6];	// MAC Address
} ArpTable, *PArpTable;


ARPAPI BOOL WINAPI InitSNMPLib();
ARPAPI int WINAPI GetEntries(ArpTable* pTable, int TableLength, int AdapterIndex);

#endif
