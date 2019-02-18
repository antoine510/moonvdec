#pragma once

#define CALLBACK_CONV __stdcall
#ifdef MOONVDEC_EXPORT
#define API_EXPORT __declspec(dllexport)
#else
#define API_EXPORT __declspec(dllimport)
#endif

#include "Limelight.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef void* mvd_StreamSource;

	typedef void(CALLBACK_CONV* mvd_CLogCallback)(const char* msg);
	typedef void(CALLBACK_CONV* mvd_CFrameCallback)(const uint8_t* frameNV12, void* context);

	API_EXPORT int mvd_Init(mvd_CLogCallback cb);
	API_EXPORT void mvd_Close();

	API_EXPORT mvd_StreamSource mvd_GetStreamSource(const char* address);
	API_EXPORT void mvd_DiscardStreamSource(mvd_StreamSource src);

	API_EXPORT int mvd_PairStreamSource(mvd_StreamSource src, const char* PIN);
	API_EXPORT int mvd_GetAppList(mvd_StreamSource src, const int** ids, const wchar_t* const** names, const int** lengths);

	API_EXPORT void mvd_LaunchApp(mvd_StreamSource src, int appID, PSTREAM_CONFIGURATION sconfig);
	API_EXPORT int mvd_StartStream(mvd_StreamSource src, PSTREAM_CONFIGURATION sconfig,
								   mvd_CFrameCallback outFramesCB, void* outFramesContext);
	API_EXPORT void mvd_StopStream(mvd_StreamSource src);


#ifdef __cplusplus
}
#endif
