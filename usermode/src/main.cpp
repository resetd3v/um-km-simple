#include "pch.h"
//#include "test.h"
#include <iostream>

// entrypoint | 0 = success -> anything else = error
int main() {
	printf("started\n");

	// tries to download, load and connect to the driver
	if (!driver.setup()) {
		// messagebox for error
		int msgboxID = MessageBox(
			NULL,
			(LPCWSTR)L"The driver was not initialized",
			(LPCWSTR)utils::genRandStr(12).c_str(),
			MB_ICONERROR | MB_OK | MB_DEFBUTTON2
		);
		// console logging for debugging
		printf("the driver was not initialized\n");
		//std::cin.get();
		return 1;
	}

	//registerPackets();
	//if (comm.setup("", "")) {
	//	// messagebox for error
	//	int msgboxID = MessageBox(
	//		NULL,
	//		(LPCWSTR)L"The communication has failed",
	//		(LPCWSTR)utils::genRandStr(12).c_str(),
	//		MB_ICONERROR | MB_OK | MB_DEFBUTTON2
	//	);
	//	// console logging for debugging
	//	printf("the communication was not initialized\n");
	//	//std::cin.get();
	//	return 1;
	//}

	ULONG procId = NULL, threadId = NULL;

	// set actual window name to target, is normally and can be redefined by comm packet
	proc::GetProcIdThread("WindowName", &procId, &threadId);
	if (!procId || !threadId) {
		printf("invalid thread id or proc id\n");
		return 1;
	}

	driver.processId = procId;
	driver.threadId = threadId;
	printf("found proc and thread id: %p, %p\n", procId, threadId);

	// IMPLEMENT OWN LOGIC HERE !?!?!!? (use the comm system if ur epic dont impl here :3)

	std::cin.get();
	return 0;
}