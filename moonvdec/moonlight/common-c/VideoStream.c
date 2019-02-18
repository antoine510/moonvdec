#include "Limelight-internal.h"
#include "PlatformSockets.h"
#include "PlatformThreads.h"
#include "RtpFecQueue.h"

#define FIRST_FRAME_MAX 1500
#define FIRST_FRAME_TIMEOUT_SEC 10

#define RTP_PORT 47998
#define FIRST_FRAME_PORT 47996

#define RTP_RECV_BUFFER (512 * 1024)

typedef struct _VIDEO_STREAM_CTX {
	RTP_FEC_QUEUE rtpQueue;

	SOCKET rtpSocket;
	SOCKET firstFrameSocket;

	PLT_THREAD udpPingThread;
	PLT_THREAD receiveThread;
	PLT_THREAD decoderThread;
} VIDEO_STREAM_CTX, *PVIDEO_STREAM_CTX;

/*static RTP_FEC_QUEUE rtpQueue;

static SOCKET rtpSocket = INVALID_SOCKET;
static SOCKET firstFrameSocket = INVALID_SOCKET;

static PLT_THREAD udpPingThread;
static PLT_THREAD receiveThread;
static PLT_THREAD decoderThread;*/

// We can't request an IDR frame until the depacketizer knows
// that a packet was lost. This timeout bounds the time that
// the RTP queue will wait for missing/reordered packets.
#define RTP_QUEUE_DELAY 10


// Initialize the video stream
void initializeVideoStream(PLIMELIGHT_CTX ctx) {
	ctx->vstream = (PVIDEO_STREAM_CTX)calloc(1, sizeof(VIDEO_STREAM_CTX));

	ctx->vstream->rtpSocket = INVALID_SOCKET;
	ctx->vstream->firstFrameSocket = INVALID_SOCKET;
    initializeVideoDepacketizer(ctx, ctx->StreamConfig.packetSize);
    RtpfInitializeQueue(&ctx->vstream->rtpQueue); //TODO RTP_QUEUE_DELAY
}

// Clean up the video stream
void destroyVideoStream(PLIMELIGHT_CTX ctx) {
    destroyVideoDepacketizer(ctx);
    RtpfCleanupQueue(&ctx->vstream->rtpQueue);
	free(ctx->vstream);
}

// UDP Ping proc
static void UdpPingThreadProc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;
	PVIDEO_STREAM_CTX vctx = ctx->vstream;

    char pingData[] = { 0x50, 0x49, 0x4E, 0x47 };
    struct sockaddr_in6 saddr;
    SOCK_RET err;

    memcpy(&saddr, &ctx->RemoteAddr, sizeof(saddr));
    saddr.sin6_port = htons(RTP_PORT);

    while (!PltIsThreadInterrupted(&vctx->udpPingThread)) {
        err = sendto(vctx->rtpSocket, pingData, sizeof(pingData), 0, (struct sockaddr*)&saddr, ctx->RemoteAddrLen);
        if (err != sizeof(pingData)) {
            Limelog("Video Ping: send() failed: %d\n", (int)LastSocketError());
            ctx->connectionTerminatedInternal(ctx, LastSocketError());
            return;
        }

        PltSleepMs(500);
    }
}

// Receive thread proc
static void ReceiveThreadProc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;
	PVIDEO_STREAM_CTX vctx = ctx->vstream;

    int err;
    int bufferSize, receiveSize;
    char* buffer;
    int queueStatus;
    int useSelect;
    PRTPFEC_QUEUE_ENTRY queueEntry;

    receiveSize = ctx->StreamConfig.packetSize + MAX_RTP_HEADER_SIZE;
    bufferSize = receiveSize + sizeof(RTPFEC_QUEUE_ENTRY);
    buffer = NULL;

    if (setNonFatalRecvTimeoutMs(vctx->rtpSocket, UDP_RECV_POLL_TIMEOUT_MS) < 0) {
        // SO_RCVTIMEO failed, so use select() to wait
        useSelect = 1;
    }
    else {
        // SO_RCVTIMEO timeout set for recv()
        useSelect = 0;
    }

    while (!PltIsThreadInterrupted(&vctx->receiveThread)) {
        PRTP_PACKET packet;

        if (buffer == NULL) {
            buffer = (char*)malloc(bufferSize);
            if (buffer == NULL) {
                Limelog("Video Receive: malloc() failed\n");
                ctx->connectionTerminatedInternal(ctx, -1);
                return;
            }
        }

        err = recvUdpSocket(vctx->rtpSocket, buffer, receiveSize, useSelect);
        if (err < 0) {
            Limelog("Video Receive: recvUdpSocket() failed: %d\n", (int)LastSocketError());
            ctx->connectionTerminatedInternal(ctx, LastSocketError());
            break;
        }
        else if  (err == 0) {
            // Receive timed out; try again
            continue;
        }

        // RTP sequence number must be in host order for the RTP queue
        packet = (PRTP_PACKET)&buffer[0];
        packet->sequenceNumber = htons(packet->sequenceNumber);

        queueStatus = RtpfAddPacket(ctx, &vctx->rtpQueue, packet, err, (PRTPFEC_QUEUE_ENTRY)&buffer[receiveSize]);
        if (queueStatus == RTPF_RET_QUEUED_PACKETS_READY) {
            // The packet queue now has packets ready
            buffer = NULL;
            while ((queueEntry = RtpfGetQueuedPacket(&vctx->rtpQueue)) != NULL) {
                queueRtpPacket(ctx, queueEntry);
                free(queueEntry->packet);
            }
        }
        else if (queueStatus == RTPF_RET_QUEUED_NOTHING_READY) {
            // The queue owns the buffer
            buffer = NULL;
        }
    }

    if (buffer != NULL) {
        free(buffer);
    }
}

// Decoder thread proc
static void DecoderThreadProc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;
	PVIDEO_STREAM_CTX vctx = ctx->vstream;

    PQUEUED_DECODE_UNIT qdu;
    while (!PltIsThreadInterrupted(&vctx->decoderThread)) {
        if (!getNextQueuedDecodeUnit(ctx->vdepack, &qdu)) {
            return;
        }

        int ret = ctx->VideoCallbacks.submitDecodeUnit(&qdu->decodeUnit, ctx->DecodeUnitContext);

        freeQueuedDecodeUnit(qdu);

        if (ret == DR_NEED_IDR) {
            Limelog("Requesting IDR frame on behalf of DR\n");
            requestDecoderRefresh(ctx);
        }
    }
}

// Read the first frame of the video stream
int readFirstFrame(PVIDEO_STREAM_CTX vctx) {
    // All that matters is that we close this socket.
    // This starts the flow of video on Gen 3 servers.

    closeSocket(vctx->firstFrameSocket);
    vctx->firstFrameSocket = INVALID_SOCKET;

    return 0;
}

// Terminate the video stream
void stopVideoStream(PLIMELIGHT_CTX ctx) {
	PVIDEO_STREAM_CTX vctx = ctx->vstream;

    ctx->VideoCallbacks.stop();

    // Wake up client code that may be waiting on the decode unit queue
    stopVideoDepacketizer(ctx);

    PltInterruptThread(&vctx->udpPingThread);
    PltInterruptThread(&vctx->receiveThread);
    if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        PltInterruptThread(&vctx->decoderThread);
    }

    if (vctx->firstFrameSocket != INVALID_SOCKET) {
        shutdownTcpSocket(vctx->firstFrameSocket);
    }

    PltJoinThread(&vctx->udpPingThread);
    PltJoinThread(&vctx->receiveThread);
    if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        PltJoinThread(&vctx->decoderThread);
    }

    PltCloseThread(&vctx->udpPingThread);
    PltCloseThread(&vctx->receiveThread);
    if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        PltCloseThread(&vctx->decoderThread);
    }

    if (vctx->firstFrameSocket != INVALID_SOCKET) {
        closeSocket(vctx->firstFrameSocket);
		vctx->firstFrameSocket = INVALID_SOCKET;
    }
    if (vctx->rtpSocket != INVALID_SOCKET) {
        closeSocket(vctx->rtpSocket);
		vctx->rtpSocket = INVALID_SOCKET;
    }

	ctx->VideoCallbacks.cleanup();
}

// Start the video stream
int startVideoStream(PLIMELIGHT_CTX ctx, void* rendererContext, int drFlags) {
	PVIDEO_STREAM_CTX vctx = ctx->vstream;

    int err;

	vctx->firstFrameSocket = INVALID_SOCKET;

    // This must be called before the decoder thread starts submitting
    // decode units
    LC_ASSERT(NegotiatedVideoFormat != 0);
    err = ctx->VideoCallbacks.setup(ctx->NegotiatedVideoFormat, ctx->StreamConfig.width,
									ctx->StreamConfig.height, ctx->StreamConfig.fps, rendererContext, drFlags);
    if (err != 0) {
        return err;
    }

	vctx->rtpSocket = bindUdpSocket(ctx, ctx->RemoteAddr.ss_family, RTP_RECV_BUFFER);
    if (vctx->rtpSocket == INVALID_SOCKET) {
		ctx->VideoCallbacks.cleanup();
        return LastSocketError();
    }

	ctx->VideoCallbacks.start();

    err = PltCreateThread(ReceiveThreadProc, ctx, &vctx->receiveThread);
    if (err != 0) {
		ctx->VideoCallbacks.stop();
        closeSocket(vctx->rtpSocket);
		ctx->VideoCallbacks.cleanup();
        return err;
    }

    if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        err = PltCreateThread(DecoderThreadProc, ctx, &vctx->decoderThread);
        if (err != 0) {
			ctx->VideoCallbacks.stop();
            PltInterruptThread(&vctx->receiveThread);
            PltJoinThread(&vctx->receiveThread);
            PltCloseThread(&vctx->receiveThread);
            closeSocket(vctx->rtpSocket);
			ctx->VideoCallbacks.cleanup();
            return err;
        }
    }

    if (ctx->AppVersionQuad[0] == 3) {
        // Connect this socket to open port 47998 for our ping thread
		vctx->firstFrameSocket = connectTcpSocket(ctx, &ctx->RemoteAddr, ctx->RemoteAddrLen,
                                            FIRST_FRAME_PORT, FIRST_FRAME_TIMEOUT_SEC);
        if (vctx->firstFrameSocket == INVALID_SOCKET) {
			ctx->VideoCallbacks.stop();
            stopVideoDepacketizer(ctx);
            PltInterruptThread(&vctx->receiveThread);
            if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
                PltInterruptThread(&vctx->decoderThread);
            }
            PltJoinThread(&vctx->receiveThread);
            if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
                PltJoinThread(&vctx->decoderThread);
            }
            PltCloseThread(&vctx->receiveThread);
            if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
                PltCloseThread(&vctx->decoderThread);
            }
            closeSocket(vctx->rtpSocket);
			ctx->VideoCallbacks.cleanup();
            return LastSocketError();
        }
    }

    // Start pinging before reading the first frame so GFE knows where
    // to send UDP data
    err = PltCreateThread(UdpPingThreadProc, ctx, &vctx->udpPingThread);
    if (err != 0) {
		ctx->VideoCallbacks.stop();
        stopVideoDepacketizer(ctx);
        PltInterruptThread(&vctx->receiveThread);
        if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
            PltInterruptThread(&vctx->decoderThread);
        }
        PltJoinThread(&vctx->receiveThread);
        if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
            PltJoinThread(&vctx->decoderThread);
        }
        PltCloseThread(&vctx->receiveThread);
        if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
            PltCloseThread(&vctx->decoderThread);
        }
        closeSocket(vctx->rtpSocket);
        if (vctx->firstFrameSocket != INVALID_SOCKET) {
            closeSocket(vctx->firstFrameSocket);
			vctx->firstFrameSocket = INVALID_SOCKET;
        }
		ctx->VideoCallbacks.cleanup();
        return err;
    }

    if (ctx->AppVersionQuad[0] == 3) {
        // Read the first frame to start the flow of video
        err = readFirstFrame(vctx);
        if (err != 0) {
            stopVideoStream(ctx);
            return err;
        }
    }

    return 0;
}
