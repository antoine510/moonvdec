#pragma once

#include "Limelight.h"
#include "Platform.h"
#include "PlatformSockets.h"
#include "PlatformThreads.h"
#include "Video.h"
#include "RtpFecQueue.h"

#include <enet/enet.h>

typedef struct _VIDEO_STREAM_CTX* PVIDEO_STREAM_CTX;
typedef struct _CONNECTION_CTX* PCONNECTION_CTX;
typedef struct _CONTROL_STREAM_CTX* PCONTROL_STREAM_CTX;
typedef struct _INPUT_STREAM_CTX* PINPUT_STREAM_CTX;
typedef struct _AUDIO_STREAM_CTX* PAUDIO_STREAM_CTX;
typedef struct _RTSP_CONNECTION_CTX* PRTSP_CONNECTION_CTX;
typedef struct _VIDEO_DEPACKETIZER_CTX* PVIDEO_DEPACKETIZER_CTX;

// This callback is invoked when a connection failure occurs. It will not
// occur as a result of a call to LiStopConnection()
typedef void(*ConnListenerConnectionTerminated_Internal)(PLIMELIGHT_CTX ctx, long errorCode);

typedef struct _LIMELIGHT_CTX {
	char* RemoteAddrString;
	struct sockaddr_storage RemoteAddr;
	SOCKADDR_LEN RemoteAddrLen;
	int AppVersionQuad[4];
	STREAM_CONFIGURATION StreamConfig;
	CONNECTION_LISTENER_CALLBACKS ListenerCallbacks;
	ConnListenerConnectionTerminated_Internal connectionTerminatedInternal;
	DECODER_RENDERER_CALLBACKS VideoCallbacks;
	AUDIO_RENDERER_CALLBACKS AudioCallbacks;
	int NegotiatedVideoFormat;
	volatile int ConnectionInterrupted;
	int HighQualitySurroundEnabled;
	int OriginalVideoBitrate;
	void* DecodeUnitContext;

	PVIDEO_STREAM_CTX vstream;
	PCONNECTION_CTX connection;
	PCONTROL_STREAM_CTX cstream;
	PINPUT_STREAM_CTX istream;
	PAUDIO_STREAM_CTX astream;
	PRTSP_CONNECTION_CTX rtsp;
	PVIDEO_DEPACKETIZER_CTX vdepack;
} LIMELIGHT_CTX, *PLIMELIGHT_CTX;

// Common globals
/*extern char* RemoteAddrString;
extern struct sockaddr_storage RemoteAddr;
extern SOCKADDR_LEN RemoteAddrLen;
extern int AppVersionQuad[4];
extern STREAM_CONFIGURATION StreamConfig;
extern CONNECTION_LISTENER_CALLBACKS ListenerCallbacks;
extern DECODER_RENDERER_CALLBACKS VideoCallbacks;
extern AUDIO_RENDERER_CALLBACKS AudioCallbacks;
extern int NegotiatedVideoFormat;
extern volatile int ConnectionInterrupted;
extern int HighQualitySurroundEnabled;
extern int OriginalVideoBitrate;*/

#ifndef UINT24_MAX
#define UINT24_MAX 0xFFFFFF
#endif

#define U16(x) ((unsigned short) ((x) & UINT16_MAX))
#define U24(x) ((unsigned int) ((x) & UINT24_MAX))
#define U32(x) ((unsigned int) ((x) & UINT32_MAX))

#define isBefore16(x, y) (U16((x) - (y)) > (UINT16_MAX/2))
#define isBefore24(x, y) (U24((x) - (y)) > (UINT24_MAX/2))
#define isBefore32(x, y) (U32((x) - (y)) > (UINT32_MAX/2))

#define UDP_RECV_POLL_TIMEOUT_MS 100

int serviceEnetHost(PLIMELIGHT_CTX ctx, ENetHost* client, ENetEvent* event, enet_uint32 timeoutMs);
int extractVersionQuadFromString(const char* string, int* quad);
int isReferenceFrameInvalidationEnabled(PLIMELIGHT_CTX ctx);

void fixupMissingCallbacks(PDECODER_RENDERER_CALLBACKS* drCallbacks, PAUDIO_RENDERER_CALLBACKS* arCallbacks,
    PCONNECTION_LISTENER_CALLBACKS* clCallbacks);

char* getSdpPayloadForStreamConfig(PLIMELIGHT_CTX ctx, int rtspClientVersion, int* length);

int initializeControlStream(PLIMELIGHT_CTX ctx);
int startControlStream(PLIMELIGHT_CTX ctx);
int stopControlStream(PLIMELIGHT_CTX ctx);
void destroyControlStream(PCONTROL_STREAM_CTX clctx);
void requestIdrOnDemand(PCONTROL_STREAM_CTX clctx);
void connectionDetectedFrameLoss(PLIMELIGHT_CTX ctx, int startFrame, int endFrame);
void connectionReceivedCompleteFrame(PCONTROL_STREAM_CTX clctx, int frameIndex);
void connectionSawFrame(PCONTROL_STREAM_CTX clctx, int frameIndex);
void connectionLostPackets(PCONTROL_STREAM_CTX clctx, int lastReceivedPacket, int nextReceivedPacket);
int sendInputPacketOnControlStream(PLIMELIGHT_CTX ctx, unsigned char* data, int length);

int performRtspHandshake(PLIMELIGHT_CTX ctx);
void destroyRtspConnection(PRTSP_CONNECTION_CTX rctx);

void initializeVideoDepacketizer(PLIMELIGHT_CTX ctx, int pktSize);
void destroyVideoDepacketizer(PLIMELIGHT_CTX ctx);
void processRtpPayload(PLIMELIGHT_CTX ctx, PNV_VIDEO_PACKET videoPacket, int length, unsigned long long receiveTimeMs);
void queueRtpPacket(PLIMELIGHT_CTX ctx, PRTPFEC_QUEUE_ENTRY queueEntry);
void stopVideoDepacketizer(PLIMELIGHT_CTX ctx);
void requestDecoderRefresh(PLIMELIGHT_CTX ctx);

void initializeVideoStream(PLIMELIGHT_CTX ctx);
void destroyVideoStream(PLIMELIGHT_CTX ctx);
int startVideoStream(PLIMELIGHT_CTX ctx, void* rendererContext, int drFlags);
void stopVideoStream(PLIMELIGHT_CTX ctx);

void initializeAudioStream(PLIMELIGHT_CTX ctx);
void destroyAudioStream(PLIMELIGHT_CTX ctx);
int startAudioStream(PLIMELIGHT_CTX ctx, void* audioContext, int arFlags);
void stopAudioStream(PLIMELIGHT_CTX ctx);

int initializeInputStream(PLIMELIGHT_CTX ctx);
void destroyInputStream(PINPUT_STREAM_CTX ictx);
int startInputStream(PLIMELIGHT_CTX ctx);
int stopInputStream(PINPUT_STREAM_CTX ictx);
