#include "Limelight-internal.h"
#include "Platform.h"

typedef struct _CONNECTION_CTX {
	int stage;
	int alreadyTerminated;
	PLT_THREAD terminationCallbackThread;
	long terminationCallbackErrorCode;
} CONNECTION_CTX, *PCONNECTION_CTX;

static int instanceCount = 0;

/*static int stage = STAGE_NONE;
static ConnListenerConnectionTerminated originalTerminationCallback;
static int alreadyTerminated;
static PLT_THREAD terminationCallbackThread;
static long terminationCallbackErrorCode;

// Common globals
char* RemoteAddrString;
struct sockaddr_storage RemoteAddr;
SOCKADDR_LEN RemoteAddrLen;
int AppVersionQuad[4];
STREAM_CONFIGURATION StreamConfig;
CONNECTION_LISTENER_CALLBACKS ListenerCallbacks;
DECODER_RENDERER_CALLBACKS VideoCallbacks;
AUDIO_RENDERER_CALLBACKS AudioCallbacks;
int NegotiatedVideoFormat;
volatile int ConnectionInterrupted;
int HighQualitySurroundEnabled;
int OriginalVideoBitrate;*/

// Connection stages
static const char* stageNames[STAGE_MAX] = {
    "none",
    "platform initialization",
    "name resolution",
    "RTSP handshake",
    "control stream initialization",
    "video stream initialization",
    "audio stream initialization",
    "input stream initialization",
    "control stream establishment",
    "video stream establishment",
    "audio stream establishment",
    "input stream establishment"
};

// Get the name of the current stage based on its number
const char* LiGetStageName(int stage) {
    return stageNames[stage];
}

// Interrupt a pending connection attempt. This interruption happens asynchronously
// so it is not safe to start another connection before LiStartConnection() returns.
void LiInterruptConnection(PLIMELIGHT_CTX ctx) {
    // Signal anyone waiting on the global interrupted flag
    ctx->ConnectionInterrupted = 1;
}

// Stop the connection by undoing the step at the current stage and those before it
void LiStopConnection(PLIMELIGHT_CTX ctx) {
	PCONNECTION_CTX cctx = ctx->connection;
	if(cctx == NULL) return;

    // Disable termination callbacks now
	cctx->alreadyTerminated = 1;

    // Set the interrupted flag
    LiInterruptConnection(ctx);

    if (cctx->stage == STAGE_INPUT_STREAM_START) {
        Limelog("Stopping input stream...");
        stopInputStream(ctx->istream);
        cctx->stage--;
        Limelog("done\n");
    }
    if (cctx->stage == STAGE_AUDIO_STREAM_START) {
        Limelog("Stopping audio stream...");
        stopAudioStream(ctx);
        cctx->stage--;
        Limelog("done\n");
    }
    if (cctx->stage == STAGE_VIDEO_STREAM_START) {
        Limelog("Stopping video stream...");
        stopVideoStream(ctx);
        cctx->stage--;
        Limelog("done\n");
    }
    if (cctx->stage == STAGE_CONTROL_STREAM_START) {
        Limelog("Stopping control stream...");
        stopControlStream(ctx);
        cctx->stage--;
        Limelog("done\n");
    }
    if (cctx->stage == STAGE_INPUT_STREAM_INIT) {
        Limelog("Cleaning up input stream...");
        destroyInputStream(ctx->istream);
        cctx->stage--;
        Limelog("done\n");
    }
    if (cctx->stage == STAGE_AUDIO_STREAM_INIT) {
        Limelog("Cleaning up audio stream...");
        destroyAudioStream(ctx);
        cctx->stage--;
        Limelog("done\n");
    }
    if (cctx->stage == STAGE_VIDEO_STREAM_INIT) {
        Limelog("Cleaning up video stream...");
        destroyVideoStream(ctx);
        cctx->stage--;
        Limelog("done\n");
    }
    if (cctx->stage == STAGE_CONTROL_STREAM_INIT) {
        Limelog("Cleaning up control stream...");
        destroyControlStream(ctx->cstream);
        cctx->stage--;
        Limelog("done\n");
    }
    if (cctx->stage == STAGE_RTSP_HANDSHAKE) {
		destroyRtspConnection(ctx->rtsp);
        cctx->stage--;
    }
    if (cctx->stage == STAGE_NAME_RESOLUTION) {
        // Nothing to do
        cctx->stage--;
    }
    if (cctx->stage == STAGE_PLATFORM_INIT) {
		instanceCount--;
		if(instanceCount == 0) {
			Limelog("Cleaning up platform...");
			cleanupPlatform();
			Limelog("done\n");
		}
        cctx->stage--;
    }
    LC_ASSERT(cctx->stage == STAGE_NONE);

    if (ctx->RemoteAddrString != NULL) {
        free(ctx->RemoteAddrString);
        ctx->RemoteAddrString = NULL;
    }

	free(ctx->connection);
	ctx->connection = NULL;
}

static void terminationCallbackThreadFunc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;

    // Invoke the client's termination callback
	ctx->ListenerCallbacks.connectionTerminated(ctx->connection->terminationCallbackErrorCode);
}

// This shim callback runs the client's connectionTerminated() callback on a
// separate thread. This is neccessary because other internal threads directly
// invoke this callback. That can result in a deadlock if the client
// calls LiStopConnection() in the callback when the cleanup code
// attempts to join the thread that the termination callback (and LiStopConnection)
// is running on.
static void ClInternalConnectionTerminated(PLIMELIGHT_CTX ctx, long errorCode) {
	PCONNECTION_CTX cctx = ctx->connection;

    int err;

    // Avoid recursion and issuing multiple callbacks
    if (cctx->alreadyTerminated) {
        return;
    }

	cctx->alreadyTerminated = 1;

    // Invoke the termination callback on a separate thread
    err = PltCreateThread(terminationCallbackThreadFunc, ctx, &cctx->terminationCallbackThread);
    if (err != 0) {
        // Nothing we can safely do here, so we'll just assert on debug builds
        Limelog("Failed to create termination thread: %d\n", err);
        LC_ASSERT(err == 0);
    }

    // Close the thread handle since we can never wait on it
    PltCloseThread(&cctx->terminationCallbackThread);
}

PLIMELIGHT_CTX LiCreateContext() {
	return (PLIMELIGHT_CTX)calloc(1, sizeof(LIMELIGHT_CTX));
}

void LiDestroyContext(PLIMELIGHT_CTX ctx) {
	free(ctx);
}

// Starts the connection to the streaming machine
int LiStartConnection(PLIMELIGHT_CTX ctx, PSERVER_INFORMATION serverInfo, PSTREAM_CONFIGURATION streamConfig, PCONNECTION_LISTENER_CALLBACKS clCallbacks,
    PDECODER_RENDERER_CALLBACKS drCallbacks, PAUDIO_RENDERER_CALLBACKS arCallbacks, void* renderContext, int drFlags,
    void* audioContext, int arFlags, void* decodeUnitContext) {
	ctx->connection = (PCONNECTION_CTX)calloc(1, sizeof(CONNECTION_CTX));
	PCONNECTION_CTX cctx = ctx->connection;

	cctx->stage = STAGE_NONE;

    int err;

    ctx->NegotiatedVideoFormat = 0;
    memcpy(&ctx->StreamConfig, streamConfig, sizeof(ctx->StreamConfig));
	ctx->OriginalVideoBitrate = streamConfig->bitrate;
	ctx->RemoteAddrString = _strdup(serverInfo->address);
	ctx->DecodeUnitContext = decodeUnitContext;

    // FEC only works in 16 byte chunks, so we must round down
    // the given packet size to the nearest multiple of 16.
	ctx->StreamConfig.packetSize -= ctx->StreamConfig.packetSize % 16;

    // Extract the appversion from the supplied string
    if (extractVersionQuadFromString(serverInfo->serverInfoAppVersion,
									 ctx->AppVersionQuad) < 0) {
        Limelog("Invalid appversion string: %s\n", serverInfo->serverInfoAppVersion);
        return -1;
    }

    // Replace missing callbacks with placeholders
    fixupMissingCallbacks(&drCallbacks, &arCallbacks, &clCallbacks);
    memcpy(&ctx->VideoCallbacks, drCallbacks, sizeof(ctx->VideoCallbacks));
    memcpy(&ctx->AudioCallbacks, arCallbacks, sizeof(ctx->AudioCallbacks));

    // Hook the termination callback so we can avoid issuing a termination callback
    // after LiStopConnection() is called
    memcpy(&ctx->ListenerCallbacks, clCallbacks, sizeof(ctx->ListenerCallbacks));
	ctx->connectionTerminatedInternal = ClInternalConnectionTerminated;

	cctx->alreadyTerminated = 0;
	ctx->ConnectionInterrupted = 0;

	// Platform init common to all instances
	if(instanceCount == 0) {
		Limelog("Initializing platform...");
		ctx->ListenerCallbacks.stageStarting(STAGE_PLATFORM_INIT);
		int err = initializePlatform();
		if(err != 0) {
			Limelog("failed: %d\n", err);
			ctx->ListenerCallbacks.stageFailed(STAGE_PLATFORM_INIT, err);
			goto Cleanup;
		}
		instanceCount++;
		cctx->stage++;
		LC_ASSERT(cctx->stage == STAGE_PLATFORM_INIT);
		ctx->ListenerCallbacks.stageComplete(STAGE_PLATFORM_INIT);
		Limelog("done\n");
	} else {
		instanceCount++;
		cctx->stage++;
	}


    Limelog("Resolving host name...");
	ctx->ListenerCallbacks.stageStarting(STAGE_NAME_RESOLUTION);
    err = resolveHostName(ctx, serverInfo->address, &ctx->RemoteAddr, &ctx->RemoteAddrLen);
    if (err != 0) {
        Limelog("failed: %d\n", err);
		ctx->ListenerCallbacks.stageFailed(STAGE_NAME_RESOLUTION, err);
        goto Cleanup;
    }
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_NAME_RESOLUTION);
	ctx->ListenerCallbacks.stageComplete(STAGE_NAME_RESOLUTION);
    Limelog("done\n");

    Limelog("Starting RTSP handshake...");
	ctx->ListenerCallbacks.stageStarting(STAGE_RTSP_HANDSHAKE);
    err = performRtspHandshake(ctx);
    if (err != 0) {
        Limelog("failed: %d\n", err);
		ctx->ListenerCallbacks.stageFailed(STAGE_RTSP_HANDSHAKE, err);
        goto Cleanup;
    }
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_RTSP_HANDSHAKE);
	ctx->ListenerCallbacks.stageComplete(STAGE_RTSP_HANDSHAKE);
    Limelog("done\n");

    Limelog("Initializing control stream...");
	ctx->ListenerCallbacks.stageStarting(STAGE_CONTROL_STREAM_INIT);
    err = initializeControlStream(ctx);
    if (err != 0) {
        Limelog("failed: %d\n", err);
		ctx->ListenerCallbacks.stageFailed(STAGE_CONTROL_STREAM_INIT, err);
        goto Cleanup;
    }
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_CONTROL_STREAM_INIT);
	ctx->ListenerCallbacks.stageComplete(STAGE_CONTROL_STREAM_INIT);
    Limelog("done\n");

    Limelog("Initializing video stream...");
	ctx->ListenerCallbacks.stageStarting(STAGE_VIDEO_STREAM_INIT);
    initializeVideoStream(ctx);
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_VIDEO_STREAM_INIT);
	ctx->ListenerCallbacks.stageComplete(STAGE_VIDEO_STREAM_INIT);
    Limelog("done\n");

    Limelog("Initializing audio stream...");
	ctx->ListenerCallbacks.stageStarting(STAGE_AUDIO_STREAM_INIT);
    initializeAudioStream(ctx);
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_AUDIO_STREAM_INIT);
	ctx->ListenerCallbacks.stageComplete(STAGE_AUDIO_STREAM_INIT);
    Limelog("done\n");

    Limelog("Initializing input stream...");
	ctx->ListenerCallbacks.stageStarting(STAGE_INPUT_STREAM_INIT);
    initializeInputStream(ctx);
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_INPUT_STREAM_INIT);
	ctx->ListenerCallbacks.stageComplete(STAGE_INPUT_STREAM_INIT);
    Limelog("done\n");

    Limelog("Starting control stream...");
	ctx->ListenerCallbacks.stageStarting(STAGE_CONTROL_STREAM_START);
    err = startControlStream(ctx);
    if (err != 0) {
        Limelog("failed: %d\n", err);
		ctx->ListenerCallbacks.stageFailed(STAGE_CONTROL_STREAM_START, err);
        goto Cleanup;
    }
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_CONTROL_STREAM_START);
	ctx->ListenerCallbacks.stageComplete(STAGE_CONTROL_STREAM_START);
    Limelog("done\n");

    Limelog("Starting video stream...");
	ctx->ListenerCallbacks.stageStarting(STAGE_VIDEO_STREAM_START);
    err = startVideoStream(ctx, renderContext, drFlags);
    if (err != 0) {
        Limelog("Video stream start failed: %d\n", err);
		ctx->ListenerCallbacks.stageFailed(STAGE_VIDEO_STREAM_START, err);
        goto Cleanup;
    }
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_VIDEO_STREAM_START);
	ctx->ListenerCallbacks.stageComplete(STAGE_VIDEO_STREAM_START);
    Limelog("done\n");

    Limelog("Starting audio stream...");
	ctx->ListenerCallbacks.stageStarting(STAGE_AUDIO_STREAM_START);
    err = startAudioStream(ctx, audioContext, arFlags);
    if (err != 0) {
        Limelog("Audio stream start failed: %d\n", err);
		ctx->ListenerCallbacks.stageFailed(STAGE_AUDIO_STREAM_START, err);
        goto Cleanup;
    }
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_AUDIO_STREAM_START);
	ctx->ListenerCallbacks.stageComplete(STAGE_AUDIO_STREAM_START);
    Limelog("done\n");

    Limelog("Starting input stream...");
	ctx->ListenerCallbacks.stageStarting(STAGE_INPUT_STREAM_START);
    err = startInputStream(ctx);
    if (err != 0) {
        Limelog("Input stream start failed: %d\n", err);
		ctx->ListenerCallbacks.stageFailed(STAGE_INPUT_STREAM_START, err);
        goto Cleanup;
    }
	cctx->stage++;
    LC_ASSERT(cctx->stage == STAGE_INPUT_STREAM_START);
	ctx->ListenerCallbacks.stageComplete(STAGE_INPUT_STREAM_START);
    Limelog("done\n");

    // Wiggle the mouse a bit to wake the display up
    LiSendMouseMoveEvent(ctx, 1, 1);
    PltSleepMs(10);
    LiSendMouseMoveEvent(ctx, -1, -1);
    PltSleepMs(10);

	ctx->ListenerCallbacks.connectionStarted();

Cleanup:
    if (err != 0) {
        // Undo any work we've done here before failing
        LiStopConnection(ctx);
    }
    return err;
}
