#include "moonvdec.h"
#include "QtHandle.h"
#include "NvDecoder/NvDecoder.h"

#include "moonlight/session/nvhttp.h"
#include "moonlight/session/nvcomputer.h"
#include "moonlight/session/nvpairingmanager.h"

#include <QtNetwork/QNetworkProxy>
#include <string>
#include <string_view>

#define MAX_INPUT_FRAME_LENGTH 1000000

mvd_CLogCallback logCB = nullptr;

struct SourceContext {
	PLIMELIGHT_CTX limelightCtx = nullptr;
	CUcontext decodeCtx = nullptr;
	NvDecoder* decoder = nullptr;
	uint8_t* inFrame = nullptr;
	std::function<void(const uint8_t*)> outFrameCB;
};

std::unordered_map<NvComputer*, SourceContext> contexts;
CUdevice decodeDevice;

void quickLog(const std::string& s) { if(logCB) logCB(s.c_str()); }
void quickLog(const std::string& s1, const std::string& s2) { quickLog(s1 + s2); }
void quickLog(const std::string& s1, const std::string& s2, const std::string& s3, const std::string& s4) { quickLog(s1 + s2 + s3 + s4); }


void InitializeDecoder(SourceContext& src) {
	if(cuCtxCreate(&src.decodeCtx, 0, decodeDevice) != CUDA_SUCCESS) {
		quickLog("Could not create CUDA context");
		return;
	}
	src.decoder = new NvDecoder(src.decodeCtx, 0, 0, false, cudaVideoCodec_H264, NULL, true);
	src.inFrame = new uint8_t[MAX_INPUT_FRAME_LENGTH];
}

// Calling multiple times is safe
void DestroyDecoder(SourceContext& src) {
	delete[] src.inFrame;
	src.inFrame = nullptr;

	delete src.decoder;
	src.decoder = nullptr;

	if(src.decodeCtx != nullptr) {
		if(cuCtxDestroy(src.decodeCtx) != CUDA_SUCCESS) {
			quickLog("Could not destroy CUDA context");
		}
		src.decodeCtx = nullptr;
	}
}

int mvd_Init(mvd_CLogCallback cb) {
	if(contexts.size() != 0) {
		quickLog("Double initialization is forbidden. Please use mvd_Close.");
		return -1;
	}
	logCB = cb;

	QtHandle::instance().start();
	if(!QSslSocket::supportsSsl()) {
		quickLog("Qt cannot find SSL support. Check for libeay32.dll and ssleay32.dll");
		QtHandle::instance().stop();
		return -1;
	}

	// We don't want system proxies to apply to us
	QNetworkProxyFactory::setUseSystemConfiguration(false);

	// Clear any default application proxy
	QNetworkProxy noProxy(QNetworkProxy::NoProxy);
	QNetworkProxy::setApplicationProxy(noProxy);

	// Setting up CUDA decoding device
	cuInit(0);

	int count = 0;
	if(cuDeviceGetCount(&count) != CUDA_SUCCESS || count == 0) {
		quickLog("No available CUDA device");
		return -1;
	}
	if(cuDeviceGet(&decodeDevice, 0) != CUDA_SUCCESS) {
		quickLog("Could not get device 0");
		return -1;
	}
	char szDeviceName[1024];
	cuDeviceGetName(szDeviceName, sizeof(szDeviceName), decodeDevice);
	quickLog("GPU for decode: ", szDeviceName);

	return 0;
}

void mvd_Close() {
	for(auto& src : contexts) {
		delete src.first;
		DestroyDecoder(src.second);
		LiDestroyContext(src.second.limelightCtx);
	}
	contexts.clear();

	QtHandle::instance().stop();

	logCB = nullptr;
}

mvd_StreamSource mvd_GetStreamSource(const char* address) {
	try {
		NvHTTP http(address);
		QString serverInfo = http.getServerInfo(NvHTTP::NvLogLevel::VERBOSE);
		auto tmp = new NvComputer(address, serverInfo);

		contexts.emplace(tmp, SourceContext());
		contexts.at(tmp).limelightCtx = LiCreateContext();

		return (mvd_StreamSource)tmp;
	} catch(const std::exception& e) {
		quickLog("Critical error: ", e.what());
		return nullptr;
	}
}

void mvd_DiscardStreamSource(mvd_StreamSource src) {
	auto source = (NvComputer*)src;

	delete source;
	DestroyDecoder(contexts.at(source));
	LiDestroyContext(contexts.at(source).limelightCtx);
	contexts.erase(source);
}

int mvd_PairStreamSource(mvd_StreamSource src, const char* PIN) {
	try {
		auto sourceComputer = (NvComputer*)src;
		if(sourceComputer->pairState != NvComputer::PairState::PS_PAIRED) {
			NvPairingManager pairman(sourceComputer->activeAddress);
			if(pairman.pair(sourceComputer->appVersion, PIN) != NvPairingManager::PairState::PAIRED) {
				quickLog("Could not pair");
				return -1;
			}
		}
	} catch(const std::exception& e) {
		quickLog("Critical error: ", e.what());
		return -1;
	}
	return 0;
}

int mvd_GetAppList(mvd_StreamSource src, const int** ids, const wchar_t* const** names, const int** lengths) {
	try {
		static std::vector<int> idsCache, lenCache;
		static std::vector<const wchar_t*> namesCache;

		auto sourceComputer = (NvComputer*)src;
		if(sourceComputer->pairState != NvComputer::PairState::PS_PAIRED) {
			auto bytes = sourceComputer->name.toUtf8();
			quickLog("Cannot get applist of unpaired host: ", std::string(bytes.data(), bytes.size()));
			return -1;
		}
		sourceComputer->updateAppList();
		const auto& apps = sourceComputer->appList;

		idsCache.resize(apps.count());
		namesCache.resize(apps.count());
		lenCache.resize(apps.count());

		int i = 0;
		for(const auto& app : apps) {
			idsCache[i] = app.id;
			namesCache[i] = (const wchar_t*)app.name.constData();
			lenCache[i] = app.name.size();
			i++;
		}

		*ids = idsCache.data();
		*names = namesCache.data();
		*lengths = lenCache.data();
		return apps.count();
	} catch(const std::exception& e) {
		quickLog("Critical error: ", e.what());
		return -1;
	}
}

void mvd_LaunchApp(mvd_StreamSource src, int appID, PSTREAM_CONFIGURATION sconfig) {
	try {
		auto sourceComputer = (NvComputer*)src;
		NvHTTP http(sourceComputer->activeAddress);

		http.launchApp(appID, sconfig, true);
	} catch(const GfeHttpResponseException& e) {
		quickLog("HttpResponseException on launch app: ", e.what());
	} catch(const QtNetworkReplyException& e) {
		quickLog("NetworkReplyException on launch app: ", e.what());
	} catch(const std::exception& e) {
		quickLog("Critical error: ", e.what());
	}
}

int handleDecodeUnit(PDECODE_UNIT du, void* context) {
	auto& src = *(SourceContext*)context;

	if(src.decodeCtx == nullptr) InitializeDecoder(src);

	PLENTRY entry = du->bufferList;

	if(du->fullLength > MAX_INPUT_FRAME_LENGTH) {
		quickLog("Not enough space for input frame");
		return 0;
	}

	int offset = 0;
	while(entry != nullptr) {
		memcpy(src.inFrame + offset, entry->data, entry->length);
		offset += entry->length;
		entry = entry->next;
	}

	int outFrameCount = 0;

	uint8_t** outFrames;
	if(src.decoder->Decode(src.inFrame, offset, &outFrames, &outFrameCount, CUVID_PKT_ENDOFPICTURE, nullptr, du->frameNumber) != true) {
		quickLog("Error on decode");
		return 0;
	}

	if(outFrameCount != 1) {
		quickLog("Error received frame count: ", std::to_string(outFrameCount).c_str());
		return 0;
	}
	src.outFrameCB(outFrames[0]);

	return DR_OK;
}

int mvd_StartStream(mvd_StreamSource src, PSTREAM_CONFIGURATION sconfig,
					mvd_CFrameCallback outFramesCB, void* outFramesContext) {
	auto sourceComputer = (NvComputer*)src;
	auto& sourceCtx = contexts.at(sourceComputer);

	QByteArray tmpaddr = sourceComputer->activeAddress.toUtf8();
	QByteArray tmpappver = sourceComputer->appVersion.toUtf8();
	QByteArray tmpgfever = sourceComputer->gfeVersion.toUtf8();

	SERVER_INFORMATION servinfo = {0};
	servinfo.address = tmpaddr;
	servinfo.serverInfoAppVersion = tmpappver;
	servinfo.serverInfoGfeVersion = tmpgfever;

	CONNECTION_LISTENER_CALLBACKS conconfig = {0};
	conconfig.stageStarting = [](int stage) { quickLog("Stage start: ", LiGetStageName(stage)); };
	conconfig.stageComplete = [](int stage) { quickLog("Stage complete: ", LiGetStageName(stage)); };
	conconfig.stageFailed = [](int stage, long errorCode) { quickLog("Stage fail: code ", std::to_string(errorCode).c_str(), ": ", LiGetStageName(stage)); };
	conconfig.connectionStarted = []() { quickLog("Connection start"); };
	conconfig.connectionTerminated = [](long errorCode) { quickLog("Connection terminated: code ", std::to_string(errorCode).c_str()); };
	conconfig.displayMessage = [](const char* msg) { quickLog("Message: ", msg); };
	conconfig.displayTransientMessage = [](const char* msg) { quickLog("TR Message: ", msg); };
	conconfig.logMessage = [](const char* format, ...) {
		char msg[1024];
		va_list args;
		va_start(args, format);
		vsnprintf_s(msg, sizeof(msg), format, args);
		va_end(args);
		quickLog("Log: ", msg);
	};

	sourceCtx.outFrameCB = [outFramesCB, outFramesContext](const uint8_t* frame) { outFramesCB(frame, outFramesContext); };

	DECODER_RENDERER_CALLBACKS drconfig = {0};
	drconfig.setup = nullptr;
	drconfig.cleanup = nullptr;
	drconfig.start = []() { std::cout << "Decoding start" << std::endl; };
	drconfig.stop = []() { std::cout << "Decoding stop" << std::endl; };
	drconfig.submitDecodeUnit = handleDecodeUnit;
	drconfig.capabilities |= CAPABILITY_SLICES_PER_FRAME(std::min(4u, std::thread::hardware_concurrency()));

	return LiStartConnection(sourceCtx.limelightCtx, &servinfo, sconfig, &conconfig, &drconfig, nullptr, nullptr, 0, nullptr, 0, &sourceCtx);
}

void mvd_StopStream(mvd_StreamSource src) {
	auto sourceComputer = (NvComputer*)src;
	auto& sourceCtx = contexts.at(sourceComputer);
	try {
		LiStopConnection(sourceCtx.limelightCtx);
		DestroyDecoder(sourceCtx);
		sourceCtx.outFrameCB = [](const uint8_t*) {};


		NvHTTP http(sourceComputer->activeAddress);
		http.quitApp();
	} catch(const std::exception& e) {
		quickLog("Critical error: ", e.what());
	}
}
