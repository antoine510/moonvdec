#include "Limelight-internal.h"
#include "PlatformSockets.h"
#include "PlatformThreads.h"
#include "LinkedBlockingQueue.h"
#include "RtpReorderQueue.h"

typedef struct _AUDIO_STREAM_CTX {
	SOCKET rtpSocket;

	LINKED_BLOCKING_QUEUE packetQueue;
	RTP_REORDER_QUEUE rtpReorderQueue;

	PLT_THREAD udpPingThread;
	PLT_THREAD receiveThread;
	PLT_THREAD decoderThread;

	unsigned short lastSeq;
} AUDIO_STREAM_CTX, *PAUDIO_STREAM_CTX;

/*static SOCKET rtpSocket = INVALID_SOCKET;

static LINKED_BLOCKING_QUEUE packetQueue;
static RTP_REORDER_QUEUE rtpReorderQueue;

static PLT_THREAD udpPingThread;
static PLT_THREAD receiveThread;
static PLT_THREAD decoderThread;

static unsigned short lastSeq;*/

#define RTP_PORT 48000

#define MAX_PACKET_SIZE 1400

// This is much larger than we should typically have buffered, but
// it needs to be. We need a cushion in case our thread gets blocked
// for longer than normal.
#define RTP_RECV_BUFFER (64 * 1024)

#define SAMPLE_RATE 48000

static OPUS_MULTISTREAM_CONFIGURATION opusStereoConfig = {
    .sampleRate = SAMPLE_RATE,
    .channelCount = 2,
    .streams = 1,
    .coupledStreams = 1,
    .mapping = {0, 1}
};

static OPUS_MULTISTREAM_CONFIGURATION opus51SurroundConfig = {
    .sampleRate = SAMPLE_RATE,
    .channelCount = 6,
    .streams = 4,
    .coupledStreams = 2,
    .mapping = {0, 4, 1, 5, 2, 3}
};

static OPUS_MULTISTREAM_CONFIGURATION opus51HighSurroundConfig = {
        .sampleRate = SAMPLE_RATE,
        .channelCount = 6,
        .streams = 6,
        .coupledStreams = 0,
        .mapping = {0, 1, 2, 3, 4, 5}
};

typedef struct _QUEUED_AUDIO_PACKET {
    // data must remain at the front
    char data[MAX_PACKET_SIZE];

    int size;
    union {
        RTP_QUEUE_ENTRY rentry;
        LINKED_BLOCKING_QUEUE_ENTRY lentry;
    } q;
} QUEUED_AUDIO_PACKET, *PQUEUED_AUDIO_PACKET;

// Initialize the audio stream
void initializeAudioStream(PLIMELIGHT_CTX ctx) {
	ctx->astream = (PAUDIO_STREAM_CTX)calloc(1, sizeof(AUDIO_STREAM_CTX));
	PAUDIO_STREAM_CTX actx = ctx->astream;

	actx->rtpSocket = INVALID_SOCKET;
    if ((ctx->AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        LbqInitializeLinkedBlockingQueue(&actx->packetQueue, 30);
    }
    RtpqInitializeQueue(&actx->rtpReorderQueue, RTPQ_DEFAULT_MAX_SIZE, RTPQ_DEFAULT_QUEUE_TIME);
	actx->lastSeq = 0;
}

static void freePacketList(PLINKED_BLOCKING_QUEUE_ENTRY entry) {
    PLINKED_BLOCKING_QUEUE_ENTRY nextEntry;

    while (entry != NULL) {
        nextEntry = entry->flink;

        // The entry is stored within the data allocation
        free(entry->data);

        entry = nextEntry;
    }
}

// Tear down the audio stream once we're done with it
void destroyAudioStream(PLIMELIGHT_CTX ctx) {
    if ((ctx->AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        freePacketList(LbqDestroyLinkedBlockingQueue(&ctx->astream->packetQueue));
    }
    RtpqCleanupQueue(&ctx->astream->rtpReorderQueue);
	free(ctx->astream);
}

static void UdpPingThreadProc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;
	PAUDIO_STREAM_CTX actx = ctx->astream;

    // Ping in ASCII
    char pingData[] = { 0x50, 0x49, 0x4E, 0x47 };
    struct sockaddr_in6 saddr;
    SOCK_RET err;

    memcpy(&saddr, &ctx->RemoteAddr, sizeof(saddr));
    saddr.sin6_port = htons(RTP_PORT);

    // Send PING every 500 milliseconds
    while (!PltIsThreadInterrupted(&actx->udpPingThread)) {
        err = sendto(actx->rtpSocket, pingData, sizeof(pingData), 0, (struct sockaddr*)&saddr, ctx->RemoteAddrLen);
        if (err != sizeof(pingData)) {
            Limelog("Audio Ping: sendto() failed: %d\n", (int)LastSocketError());
			ctx->ListenerCallbacks.connectionTerminated(LastSocketError());
            return;
        }

        PltSleepMs(500);
    }
}

static int queuePacketToLbq(PLIMELIGHT_CTX ctx, PQUEUED_AUDIO_PACKET* packet) {
    int err;

    err = LbqOfferQueueItem(&ctx->astream->packetQueue, *packet, &(*packet)->q.lentry);
    if (err == LBQ_SUCCESS) {
        // The LBQ owns the buffer now
        *packet = NULL;
    }
    else if (err == LBQ_BOUND_EXCEEDED) {
        Limelog("Audio packet queue overflow\n");
        freePacketList(LbqFlushQueueItems(&ctx->astream->packetQueue));
    }
    else if (err == LBQ_INTERRUPTED) {
        return 0;
    }

    return 1;
}

static void decodeInputData(PLIMELIGHT_CTX ctx, PQUEUED_AUDIO_PACKET packet) {
    PRTP_PACKET rtp;

    rtp = (PRTP_PACKET)&packet->data[0];
    if (ctx->astream->lastSeq != 0 && (unsigned short)(ctx->astream->lastSeq + 1) != rtp->sequenceNumber) {
        Limelog("Received OOS audio data (expected %d, but got %d)\n", ctx->astream->lastSeq + 1, rtp->sequenceNumber);

        ctx->AudioCallbacks.decodeAndPlaySample(NULL, 0);
    }

	ctx->astream->lastSeq = rtp->sequenceNumber;

	ctx->AudioCallbacks.decodeAndPlaySample((char*)(rtp + 1), packet->size - sizeof(*rtp));
}

static void ReceiveThreadProc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;
	PAUDIO_STREAM_CTX actx = ctx->astream;

    PRTP_PACKET rtp;
    PQUEUED_AUDIO_PACKET packet;
    int queueStatus;
    int useSelect;

    packet = NULL;

    if (setNonFatalRecvTimeoutMs(actx->rtpSocket, UDP_RECV_POLL_TIMEOUT_MS) < 0) {
        // SO_RCVTIMEO failed, so use select() to wait
        useSelect = 1;
    }
    else {
        // SO_RCVTIMEO timeout set for recv()
        useSelect = 0;
    }

    while (!PltIsThreadInterrupted(&actx->receiveThread)) {
        if (packet == NULL) {
            packet = (PQUEUED_AUDIO_PACKET)malloc(sizeof(*packet));
            if (packet == NULL) {
                Limelog("Audio Receive: malloc() failed\n");
				ctx->connectionTerminatedInternal(ctx, -1);
                break;
            }
        }

        packet->size = recvUdpSocket(actx->rtpSocket, &packet->data[0], MAX_PACKET_SIZE, useSelect);
        if (packet->size < 0) {
            Limelog("Audio Receive: recvUdpSocket() failed: %d\n", (int)LastSocketError());
			ctx->connectionTerminatedInternal(ctx, LastSocketError());
            break;
        }
        else if (packet->size == 0) {
            // Receive timed out; try again
            continue;
        }

        if (packet->size < sizeof(RTP_PACKET)) {
            // Runt packet
            continue;
        }

        rtp = (PRTP_PACKET)&packet->data[0];
        if (rtp->packetType != 97) {
            // Not audio
            continue;
        }

        // RTP sequence number must be in host order for the RTP queue
        rtp->sequenceNumber = htons(rtp->sequenceNumber);

        queueStatus = RtpqAddPacket(ctx, &actx->rtpReorderQueue, (PRTP_PACKET)packet, &packet->q.rentry);
        if (RTPQ_HANDLE_NOW(queueStatus)) {
            if ((ctx->AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
                if (!queuePacketToLbq(ctx, &packet)) {
                    // An exit signal was received
                    break;
                }
            }
            else {
                decodeInputData(ctx, packet);
            }
        }
        else {
            if (RTPQ_PACKET_CONSUMED(queueStatus)) {
                // The queue consumed our packet, so we must allocate a new one
                packet = NULL;
            }

            if (RTPQ_PACKET_READY(queueStatus)) {
                // If packets are ready, pull them and send them to the decoder
                while ((packet = (PQUEUED_AUDIO_PACKET)RtpqGetQueuedPacket(&actx->rtpReorderQueue)) != NULL) {
                    if ((ctx->AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
                        if (!queuePacketToLbq(ctx, &packet)) {
                            // An exit signal was received
                            break;
                        }
                    }
                    else {
                        decodeInputData(ctx, packet);
                        free(packet);
                    }
                }

                // Break on exit
                if (packet != NULL) {
                    break;
                }
            }
        }
    }

    if (packet != NULL) {
        free(packet);
    }
}

static void DecoderThreadProc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;
	PAUDIO_STREAM_CTX actx = ctx->astream;

    int err;
    PQUEUED_AUDIO_PACKET packet;

    while (!PltIsThreadInterrupted(&actx->decoderThread)) {
        err = LbqWaitForQueueElement(&actx->packetQueue, (void**)&packet);
        if (err != LBQ_SUCCESS) {
            // An exit signal was received
            return;
        }

        decodeInputData(ctx, packet);

        free(packet);
    }
}

void stopAudioStream(PLIMELIGHT_CTX ctx) {
	PAUDIO_STREAM_CTX actx = ctx->astream;

	ctx->AudioCallbacks.stop();

    PltInterruptThread(&actx->udpPingThread);
    PltInterruptThread(&actx->receiveThread);
    if ((ctx->AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        // Signal threads waiting on the LBQ
        LbqSignalQueueShutdown(&actx->packetQueue);
        PltInterruptThread(&actx->decoderThread);
    }

    PltJoinThread(&actx->udpPingThread);
    PltJoinThread(&actx->receiveThread);
    if ((ctx->AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        PltJoinThread(&actx->decoderThread);
    }

    PltCloseThread(&actx->udpPingThread);
    PltCloseThread(&actx->receiveThread);
    if ((ctx->AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        PltCloseThread(&actx->decoderThread);
    }

    if (actx->rtpSocket != INVALID_SOCKET) {
        closeSocket(actx->rtpSocket);
		actx->rtpSocket = INVALID_SOCKET;
    }

	ctx->AudioCallbacks.cleanup();
}

int startAudioStream(PLIMELIGHT_CTX ctx, void* audioContext, int arFlags) {
	PAUDIO_STREAM_CTX actx = ctx->astream;

    int err;
    POPUS_MULTISTREAM_CONFIGURATION chosenConfig;

    if (ctx->StreamConfig.audioConfiguration == AUDIO_CONFIGURATION_STEREO) {
        chosenConfig = &opusStereoConfig;
    }
    else if (ctx->StreamConfig.audioConfiguration == AUDIO_CONFIGURATION_51_SURROUND) {
        if (ctx->HighQualitySurroundEnabled) {
            chosenConfig = &opus51HighSurroundConfig;
        }
        else {
            chosenConfig = &opus51SurroundConfig;
        }
    }
    else {
        Limelog("Invalid audio configuration: %d\n", ctx->StreamConfig.audioConfiguration);
        return -1;
    }

    err = ctx->AudioCallbacks.init(ctx->StreamConfig.audioConfiguration, chosenConfig, audioContext, arFlags);
    if (err != 0) {
        return err;
    }

	actx->rtpSocket = bindUdpSocket(ctx, ctx->RemoteAddr.ss_family, RTP_RECV_BUFFER);
    if (actx->rtpSocket == INVALID_SOCKET) {
        err = LastSocketFail();
		ctx->AudioCallbacks.cleanup();
        return err;
    }

    err = PltCreateThread(UdpPingThreadProc, ctx, &actx->udpPingThread);
    if (err != 0) {
		ctx->AudioCallbacks.cleanup();
        closeSocket(actx->rtpSocket);
        return err;
    }

	ctx->AudioCallbacks.start();

    err = PltCreateThread(ReceiveThreadProc, ctx, &actx->receiveThread);
    if (err != 0) {
		ctx->AudioCallbacks.stop();
        PltInterruptThread(&actx->udpPingThread);
        PltJoinThread(&actx->udpPingThread);
        PltCloseThread(&actx->udpPingThread);
        closeSocket(actx->rtpSocket);
		ctx->AudioCallbacks.cleanup();
        return err;
    }

    if ((ctx->AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        err = PltCreateThread(DecoderThreadProc, ctx, &actx->decoderThread);
        if (err != 0) {
			ctx->AudioCallbacks.stop();
            PltInterruptThread(&actx->udpPingThread);
            PltInterruptThread(&actx->receiveThread);
            PltJoinThread(&actx->udpPingThread);
            PltJoinThread(&actx->receiveThread);
            PltCloseThread(&actx->udpPingThread);
            PltCloseThread(&actx->receiveThread);
            closeSocket(actx->rtpSocket);
			ctx->AudioCallbacks.cleanup();
            return err;
        }
    }

    return 0;
}
