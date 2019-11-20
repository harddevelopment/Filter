#include <stdio.h>
#include "ntddk.h"
#include <fwpmk.h>
#include <fwpsk.h>
#define INITGUID
#include <guiddef.h>
#include <C:\Program Files (x86)\Windows Kits\10\Include\10.0.17763.0\um\fwpmu.h>
//#include <C:\Program Files (x86)\Windows Kits\10\Include\10.0.16299.0\um\fwpmu.h>

DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_IN , 0xd969fc67, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x36);
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_OUT, 0xd969fc67, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x37);

#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

int networkFilterStatus = 1;

PDEVICE_OBJECT DeviceObject = NULL;
HANDLE EngineHandle = NULL;
UINT32 RegCalloutIdIn = 0, AddCalloutIdIn = 0;
UINT32 RegCalloutIdOut = 0, AddCalloutIdOut = 0;
UINT64 filteridIn = 0;
UINT64 filteridOut = 0;
LARGE_INTEGER g_CmCookie = { 0 };
UINT16 port[32] = { 0 };
FWP_V4_ADDR_AND_MASK ip[32] = { 0 };
PDRIVER_OBJECT _DriverObject;

int rulesCount = 0;
UINT16 *port_src = NULL, *port_dst = NULL;
UINT32 *ip_src = NULL, *ip_dst = NULL;
unsigned char *action = NULL;
unsigned char *protocol = NULL;
char message[1024] = { 0 };

VOID UnloadDriver()
{
	KdPrint(("Unload driver... "));
	if (EngineHandle != NULL) {
		if (filteridIn != 0) {
			FwpmFilterDeleteById(EngineHandle, filteridIn);
		}

		if (AddCalloutIdIn != 0) {
			FwpmCalloutDeleteById(EngineHandle, AddCalloutIdIn);
		}

		if (RegCalloutIdIn != 0) {
			FwpsCalloutUnregisterById(RegCalloutIdIn);
		}

		if (filteridOut != 0) {
			FwpmFilterDeleteById(EngineHandle, filteridOut);
		}

		if (AddCalloutIdOut != 0) {
			FwpmCalloutDeleteById(EngineHandle, AddCalloutIdOut);
		}

		if (RegCalloutIdOut != 0) {
			FwpsCalloutUnregisterById(RegCalloutIdOut);
		}

		FwpmEngineClose(EngineHandle);
	}
	KdPrint(("OK\n"));
}


NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, const FWPS_FILTER* filter)
{
	return STATUS_SUCCESS;
}


VOID print_ip(int ip)
{
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	KdPrint(("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]));
}

VOID FilterCallbackIn(const FWPS_INCOMING_VALUES0* Values, const FWPS_INCOMING_METADATA_VALUES0* MetaData, PVOID layerdata, 
	const void* context, const FWPS_FILTER* filter, UINT64 flowcontext, FWPS_CLASSIFY_OUT* classifyout)
{
	if (networkFilterStatus == 0) {
		classifyout->actionType = FWP_ACTION_PERMIT;
		return;
	}

	UINT32 RemoteAddr = Values->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT32 LocalAddr = Values->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT16 LocalPort = Values->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 RemotePort = Values->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
	UINT8 Protocol = Values->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.int8;
	UINT32 Flag = MetaData->packetDirection;

	KdPrint(("@@%d %lu:%d %lu:%d\n", Protocol, LocalAddr, LocalPort, RemoteAddr, RemotePort));

	for (int i = 0; i < rulesCount; i++) {
		//KdPrint(("! %d %lu:%d %lu:%d\n", protocol[i], ip_src[i], port_src[i], ip_dst[i], port_dst[i]));

		if (protocol[i] == Protocol && 
			(ip_src[i] == LocalAddr || ip_src[i] == 0) &&
			(port_src[i] == LocalAddr || port_src[i] == 0) &&
			(ip_dst[i] == RemoteAddr || ip_dst[i] == 0) &&
			(port_dst[i] == RemotePort || port_dst[i] == 0)
			) {
			KdPrint(("MATCH!\n"));
			if (action[i] == 48) {
				//log
				classifyout->actionType = FWP_ACTION_PERMIT;
			}
			else if (action[i] == 49) {
				//alert
				classifyout->actionType = FWP_ACTION_PERMIT;
			}
			else if (action[i] == 50) {
				//permit
				classifyout->actionType = FWP_ACTION_PERMIT;
			}
			else {
				//block
				classifyout->actionType = FWP_ACTION_BLOCK;
			}
			return;
		}
	}
	classifyout->actionType = FWP_ACTION_PERMIT;

//	KdPrint(("%d->%d %d %x", LocalPort, RemotePort, Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.int8, Flag));
}

void int_to_ip(UINT32 ip, unsigned char bytes[4]) {
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
}

VOID FilterCallbackOut(const FWPS_INCOMING_VALUES0* Values, const FWPS_INCOMING_METADATA_VALUES0* MetaData, PVOID layerdata,
	const void* context, const FWPS_FILTER* filter, UINT64 flowcontext, FWPS_CLASSIFY_OUT* classifyout)
{
	if (networkFilterStatus == 0) {
		classifyout->actionType = FWP_ACTION_PERMIT;
		return;
	}

	UINT32 RemoteAddr = Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT32 LocalAddr = Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT16 LocalPort = Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 RemotePort = Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
	UINT8 Protocol = Values->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.int8;
	UINT32 Flag = MetaData->packetDirection;

	KdPrint(("$$%d %lu:%d %lu:%d\n", Protocol, RemoteAddr, RemotePort, LocalAddr, LocalPort));

	for (int i = 0; i < rulesCount; i++) {
		//KdPrint(("! %d %lu:%d %lu:%d\n", protocol[i], ip_src[i], port_src[i], ip_dst[i], port_dst[i]));

		if (protocol[i] == Protocol &&
			(ip_src[i] == RemoteAddr || ip_src[i] == 0) &&
			(port_src[i] == RemotePort || port_src[i] == 0) &&
			(((ip_dst[i] == LocalAddr || ip_dst[i] == 0) &&
			(port_dst[i] == LocalPort || port_dst[i] == 0)) ||
			Protocol == 1)
			) {
			KdPrint(("MATCH!\n"));
			
			if (action[i] == 48) {
				//log
				classifyout->actionType = FWP_ACTION_PERMIT;
			}
			else if (action[i] == 49) {
				//alert
				classifyout->actionType = FWP_ACTION_PERMIT;
			}
			else if (action[i] == 50) {
				//permit
				classifyout->actionType = FWP_ACTION_PERMIT;
			}
			else {
				//block
				classifyout->actionType = FWP_ACTION_BLOCK;
			}

			unsigned char ip_src_[4];
			unsigned char ip_dst_[4];

			int_to_ip(LocalAddr, ip_src_);
			int_to_ip(RemoteAddr, ip_dst_);

			KdPrint(("%u.%u.%u.%u\n", ip_src_[3], ip_src_[2], ip_src_[1], ip_src_[0] ));

			memset(message, 0, 1024);
			if (Protocol != 1)
				sprintf(message, "18%u.%u.%u.%u:%d -> %u.%u.%u.%u:%d (%d)", ip_src_[3], ip_src_[2], ip_src_[1], ip_src_[0], port_src[i], ip_dst_[3], ip_dst_[2], ip_dst_[1], ip_dst_[0], port_dst[i], action[i]);
			else
				sprintf(message, "18%u.%u.%u.%u -> %u.%u.%u.%u (%d)", ip_src_[3], ip_src_[2], ip_src_[1], ip_src_[0], ip_dst_[3], ip_dst_[2], ip_dst_[1], ip_dst_[0], action[i]);
			KdPrint(("%s\n", message));

			return;
		}
	}
	classifyout->actionType = FWP_ACTION_PERMIT;
}

NTSTATUS WfpOpenEngine()
{
	return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
}

NTSTATUS WfpRegisterCallout()
{
	NTSTATUS status;
	FWPS_CALLOUT CalloutIn = { 0 };
	CalloutIn.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_IN;
	CalloutIn.flags = 0;
	CalloutIn.classifyFn = FilterCallbackIn;
	CalloutIn.notifyFn = NotifyCallback;
	CalloutIn.flowDeleteFn = NULL; // FlowDeleteCallback;

	status = FwpsCalloutRegister1(DeviceObject, &CalloutIn, &RegCalloutIdIn);
	if (status != 0) {
		KdPrint(("WfpRegisterCallout error1\n"));
	}

	FWPS_CALLOUT CalloutOut = { 0 };
	CalloutOut.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_OUT;
	CalloutOut.flags = 0;
	CalloutOut.classifyFn = FilterCallbackOut;
	CalloutOut.notifyFn = NotifyCallback;
	CalloutOut.flowDeleteFn = NULL; // FlowDeleteCallback;

	status = FwpsCalloutRegister1(DeviceObject, &CalloutOut, &RegCalloutIdOut);
	if (status != 0) {
		KdPrint(("WfpRegisterCallout error2\n"));
	}
	return status;
}

NTSTATUS WfpAddCallout()
{
	NTSTATUS status;
	FWPM_CALLOUT calloutIn = { 0 };

	calloutIn.flags = 0;
	calloutIn.displayData.name = L"EstablishedCalloutName1";
	calloutIn.displayData.description = L"EstablishedCalloutName1";
	calloutIn.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_IN;
	calloutIn.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4;

	status = FwpmCalloutAdd(EngineHandle, &calloutIn, NULL, &AddCalloutIdIn);
	if (status != 0) {
		KdPrint(("AddCallout error1\n"));
	}

	FWPM_CALLOUT calloutOut = { 0 };

	calloutOut.flags = 0;
	calloutOut.displayData.name = L"EstablishedCalloutName2";
	calloutOut.displayData.description = L"EstablishedCalloutName2";
	calloutOut.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_OUT;
	calloutOut.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

	status = FwpmCalloutAdd(EngineHandle, &calloutOut, NULL, &AddCalloutIdOut);
	if (status != 0) {
		KdPrint(("AddCallout error2\n"));
	}
	return status;
}


NTSTATUS WfpAddFilter()
{
	NTSTATUS status;
	FWPM_FILTER_CONDITION condition = { 0 };
	FWPM_FILTER filter = { 0 };

	filter.displayData.name = L"network filter";
	filter.displayData.description = L"network filter";
	filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 0;
	filter.filterCondition = 0;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_IN;
	
	status =  FwpmFilterAdd(EngineHandle, &filter, NULL, &filteridIn);
	if (status != 0) {
		KdPrint(("WfpAddFilter error1\n"));
	}

	filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
	filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID_OUT;
	status = FwpmFilterAdd(EngineHandle, &filter, NULL, &filteridOut);
	if (status != 0) {
		KdPrint(("WfpAddFilter error2\n"));
	}
	return status;
}

WCHAR* read(WCHAR* path, WCHAR* key) {
	NTSTATUS status;
	LPWSTR DataString = NULL;

	HANDLE handleRegKey = NULL;
	UNICODE_STRING RegistryKeyName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	RtlInitUnicodeString(&RegistryKeyName, path);
	InitializeObjectAttributes(&ObjectAttributes, &RegistryKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&handleRegKey, KEY_READ, &ObjectAttributes);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Not opened\r\n"));
		if (handleRegKey != NULL) {
			ZwClose(handleRegKey);
		}
		return NULL;
	}

	PKEY_VALUE_FULL_INFORMATION pKeyInfo = NULL;
	UNICODE_STRING ValueName;
	ULONG ulKeyInfoSize = 0;
	ULONG ulKeyInfoSizeNeeded = 0;
	RtlInitUnicodeString(&ValueName, key);
	status = ZwQueryValueKey(handleRegKey, &ValueName, KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &ulKeyInfoSizeNeeded);

	if ((status == STATUS_BUFFER_TOO_SMALL) || (status == STATUS_BUFFER_OVERFLOW)) {
		ulKeyInfoSize = ulKeyInfoSizeNeeded;
		pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSizeNeeded, 'uav1');
		if (NULL == pKeyInfo) {
			if (handleRegKey != NULL) {
				ZwClose(handleRegKey);
			}
			return NULL;
		}
		RtlZeroMemory(pKeyInfo, ulKeyInfoSize);
		status = ZwQueryValueKey(handleRegKey, &ValueName, KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &ulKeyInfoSizeNeeded);
		if ((status != STATUS_SUCCESS) || (ulKeyInfoSizeNeeded != ulKeyInfoSize) || (NULL == pKeyInfo)) {
			if (handleRegKey != NULL) {
				ZwClose(handleRegKey);
			}
			if (pKeyInfo != NULL) {
				ExFreePoolWithTag(pKeyInfo, 'uav1');
			}
			return NULL;
		}

		ULONG Value_len = pKeyInfo->DataLength;
		ULONG_PTR pSrc;
		pSrc = (ULONG_PTR)((char*)pKeyInfo + pKeyInfo->DataOffset);
		DataString = (LPWSTR)ExAllocatePoolWithTag(NonPagedPool, Value_len, 'uav2');
		if (NULL == DataString) {
			if (handleRegKey != NULL) {
				ZwClose(handleRegKey);
			}
			if (pKeyInfo != NULL) {
				ExFreePoolWithTag(pKeyInfo, 'uav1');
			}
			Value_len = 0;
			return NULL;
		}
		RtlCopyMemory(DataString, (PVOID)pSrc, Value_len);
		KdPrint(("GROUP: %ws\r\n", DataString));
		//ExFreePoolWithTag(DataString, 'uav2');
	}

	if (handleRegKey != NULL) {
		ZwClose(handleRegKey);
	}
	if (pKeyInfo != NULL) {
		ExFreePoolWithTag(pKeyInfo, 'uav1');
	}

	return DataString;
}

//action, direction, protocol, ip_src, port_src, ip_dst, port_dest
//0,0,2,192.168.3.3,*,192.168.1.4,*;2,1,3,192.168.1.3,425,*,8888;3,1,0,*,8080,192.1.4.1,77;1,0,2,*,80,192.168.1.4,*;0,0,0,192.168.1.2,*,192.168.1.4,80;

int miniPow(int a, int b)   
{
	int r = 1;
	for (int i = 0; i < b; i++)
	{
		r *= a;
	}
	return r;
}
int WideToInt(wchar_t a[])
{
	int i = 0;
	int len = wcslen(a);
	int coefficient = 0;
	int RawNumber = 0;
	int Number = 0;

	for (int k = 0; k < len; k++)
	{
		coefficient = miniPow(10, len - 1 - k);
		RawNumber = (int)a[k];
		Number = RawNumber - 48;
		i += coefficient * Number;
	}
	return i;
}

unsigned int ip_to_int(WCHAR * ip)
{
	unsigned v = 0;
	int i;
	WCHAR* start;

	start = ip;
	for (i = 0; i < 4; i++) {
		char c;
		int n = 0;
		while (1) {
			c = *start;
			start++;
			if (c >= '0' && c <= '9') {
				n *= 10;
				n += c - '0';
			}
			else if ((i < 3 && c == '.') || i == 3) {
				break;
			}
		}
		v *= 256;
		v += n;
	}
	return v;
}

void registerSnortRules() {
	WCHAR* files = read(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SupaFilter", L"SnortRules");
	KdPrint(("%ws\n", files));
	KdPrint(("%d\n", wcslen(files)));

	if (port_src != NULL) ExFreePoolWithTag(port_src, 'uav3');
	if (port_dst != NULL) ExFreePoolWithTag(port_dst, 'uav3');
	if (ip_src != NULL) ExFreePoolWithTag(ip_src, 'uav3');
	if (ip_dst != NULL) ExFreePoolWithTag(ip_dst, 'uav3');
	if (action != NULL) ExFreePoolWithTag(action, 'uav4');
	if (protocol != NULL) ExFreePoolWithTag(protocol, 'uav4');

	if (files == NULL || wcslen(files) == 0) {
		return;
	}

	int size = wcslen(files);
	for (int i = 0; i < size; i++) {
		if (files[i] == ';') {
			rulesCount++;
		}
	}

	KdPrint(("%d %d\n", size, rulesCount));

	port_src = (UINT16*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT16) * rulesCount, 'uav3');
	port_dst = (UINT16*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT16) * rulesCount, 'uav3');

	ip_src = (UINT32*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT32) * rulesCount, 'uav3');
	ip_dst = (UINT32*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT32) * rulesCount, 'uav3');

	action = (unsigned char*)ExAllocatePoolWithTag(NonPagedPool, rulesCount, 'uav4');

	protocol = (unsigned char*)ExAllocatePoolWithTag(NonPagedPool, rulesCount, 'uav4');

	int currentItem = 0;
	WCHAR* file;
	for (int i = 0, ind = 0; i < size && files[i] != '\0'; i++) {
		if (files[i] == ',') {
			continue;
		}
		if (files[i] == ';') {
			currentItem = 0;
			ind += 1;
			continue;
		}
		if (currentItem == 0)
			action[ind] = files[i];
		else if (currentItem == 1)
			protocol[ind] = files[i] - 48;
		else {
			file = files + i;
			while (1) {
				if (files[i] == ',' || files[i] == '\0' || i == size || files[i] == ';') {
					int update_flag = 0;
					if (files[i] == ';') {
						update_flag = 1;
					}
					files[i] = '\0';

					int any = 0;
					if (files[i - 1] == '*') {
						any = 1;
					}

					if (currentItem == 2) {
						if (any == 1)
							ip_src[ind] = 0;
						else
							ip_src[ind] = ip_to_int(file);
					}
					else if (currentItem == 3) {
						if (any == 1)
							port_src[ind] = 0;
						else
							port_src[ind] = WideToInt(file);
					}
					else if (currentItem == 4) {
						if (any == 1)
							ip_dst[ind] = 0;
						else
							ip_dst[ind] = ip_to_int(file);
					}
					else if (currentItem == 5) {
						if (any == 1)
							port_dst[ind] = 0;
						else
							port_dst[ind] = WideToInt(file);
					}

					if (update_flag) {
						currentItem = -1;
						ind += 1;
					}

					break;
				}
				else {
					i++;
				}
			}
		}
		currentItem++;
	}

	ExFreePoolWithTag(files, 'uav2');
}


NTSTATUS InitializeWfp()
{
	KdPrint(("Start driver... "));

	registerSnortRules();

	NTSTATUS status;
	status = WfpOpenEngine();
	if (!NT_SUCCESS(status)) {
		KdPrint(("1\n"));
		goto end;
	}

	status = WfpRegisterCallout();
	if (!NT_SUCCESS(status)) {
		KdPrint(("2\n"));
		goto end;
	}

	status = WfpAddCallout();
	if (!NT_SUCCESS(status)) {
		KdPrint(("3\n"));
		goto end;
	}

	status = WfpAddFilter();
	if (!NT_SUCCESS(status)) {
		KdPrint(("4\n"));
		goto end;
	}

	KdPrint(("OK\n"));

	return STATUS_SUCCESS;
	KdPrint(("lol"));
end:
	KdPrint(("%x\n", status));
	KdPrint(("lol2"));
	UnloadDriver();
	KdPrint(("Failed\n"));
	return STATUS_UNSUCCESSFUL;
}


NTSTATUS IoctlHandler(IN PDEVICE_OBJECT fdo, IN PIRP irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG returnLength = 0;
	PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(irp);
	ULONG ControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

	//pBuffer = irp->UserBuffer;

	//KdPrint(("ControlCode %x\n", ControlCode));
	PVOID buffer;

	switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case DEVICE_SEND:
		KdPrint(("DEVICE_SEND\n"));
		char *msg = (char*)irp->UserBuffer;
		if (msg[0] == 0) {
			registerSnortRules();
		}
		else {
			networkFilterStatus = msg[0] - 2;
		}
		KdPrint(("%d\n", networkFilterStatus));
		returnLength = 0;// (strnlen(buffer, 511) + 1) * 2;
		break;
	case DEVICE_REC:
		buffer = irp->AssociatedIrp.SystemBuffer;
		wcsncpy(buffer, message, 511);
			returnLength = (strnlen(message, 511) + 1) * 2;
			memset(message, 0, 1024);
		break;
	default:
		status = STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = returnLength;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UnloadDriver();

	UNICODE_STRING deviceLink;
	RtlInitUnicodeString(&deviceLink, L"\\??\\Filter");
	IoDeleteSymbolicLink(&deviceLink);
	IoDeleteDevice(DeviceObject);
}

NTSTATUS IoctlCreate(IN PDEVICE_OBJECT fdo, IN PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS IoctlClose(IN PDEVICE_OBJECT fdo, IN PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	UNICODE_STRING devLink;
	UNICODE_STRING devName;

	_DriverObject = DriverObject;

	RtlInitUnicodeString(&devName, L"\\Device\\Filter");
	RtlInitUnicodeString(&devLink, L"\\??\\Filter");

	DriverObject->DriverUnload = Unload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IoctlCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IoctlClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlHandler;
	
	status = IoCreateDevice(DriverObject, sizeof(PDEVICE_OBJECT), &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	KdPrint(("IoCreateDevice %x\n", status));

	status = InitializeWfp();
	KdPrint(("InitializeWfp %x\n", status));
	
	status = IoCreateSymbolicLink(&devLink, &devName);
	KdPrint(("InitializeWfp %x\n", status));

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
	}

	return status;
}