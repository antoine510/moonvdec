#include "moonvdec.h"
#include "Limelight.h"
#include <iostream>
#include <string>
#include <string_view>

int main() {
	if(mvd_Init([](const char* msg) { std::cout << msg << std::endl; }) != 0) return -1;
	atexit(mvd_Close);

	auto ss = mvd_GetStreamSource("127.0.0.1");
	if(ss == nullptr) return -1;

	int res = mvd_PairStreamSource(ss, "2566");
	if(res != 0) return -1;

	const int* ids, *lens;
	const wchar_t* const* names;
	int count = mvd_GetAppList(ss, &ids, &names, &lens);
	if(count < 0) return -1;

	for(int i = 0; i < count; ++i) {
		std::wcout << std::to_wstring(i) << L". " << std::wstring_view(names[i], lens[i]) << std::endl;
	}

	mvd_StreamConfiguration sconfig = {0};
	sconfig.width = 1280;
	sconfig.height = 720;
	sconfig.fps = 30;
	sconfig.bitrate = 6000;
	sconfig.packetSize = 1024;
	sconfig.streamingRemotely = (int)false;
	sconfig.audioConfiguration = AUDIO_CONFIGURATION_STEREO;
	sconfig.supportsHevc = (int)false;
	sconfig.enableHdr = (int)false;
	sconfig.hevcBitratePercentageMultiplier = 75;
	sconfig.clientRefreshRateX100 = 5994;

	bool exit = false;
	std::string cmd;
	do {
		std::cin >> cmd;
		if(cmd == "launch") {
			int index;
			std::cin >> index;
			if(index < 1 || index > count) {
				std::cout << "Index of app out of range" << std::endl;
			} else {
				mvd_LaunchApp(ss, ids[index], &sconfig);
			}
		} else if(cmd == "start") {
			mvd_StartStream(ss, &sconfig, [](const uint8_t* data, void* context) {}, nullptr);
		} else if(cmd == "stop") {
			mvd_StopStream(ss);
		} else if(cmd == "quit") {
			exit = true;
		} else {
			std::cout << "Unknown command" << std::endl;
		}
		cmd.clear();
	} while(!exit);

	return 0;
}
