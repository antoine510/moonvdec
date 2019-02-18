#include "Limelight-internal.h"
#include "PlatformSockets.h"
#include "PlatformThreads.h"

#include "ByteBuffer.h"

#include <enet/enet.h>

// NV control stream packet header for TCP
typedef struct _NVCTL_TCP_PACKET_HEADER {
    unsigned short type;
    unsigned short payloadLength;
} NVCTL_TCP_PACKET_HEADER, *PNVCTL_TCP_PACKET_HEADER;

typedef struct _NVCTL_ENET_PACKET_HEADER {
    unsigned short type;
} NVCTL_ENET_PACKET_HEADER, *PNVCTL_ENET_PACKET_HEADER;

typedef struct _QUEUED_FRAME_INVALIDATION_TUPLE {
    int startFrame;
    int endFrame;
    LINKED_BLOCKING_QUEUE_ENTRY entry;
} QUEUED_FRAME_INVALIDATION_TUPLE, *PQUEUED_FRAME_INVALIDATION_TUPLE;


typedef struct _CONTROL_STREAM_CTX {
	SOCKET ctlSock;
	ENetHost* client;
	ENetPeer* peer;
	PLT_MUTEX enetMutex;

	PLT_THREAD lossStatsThread;
	PLT_THREAD invalidateRefFramesThread;
	PLT_EVENT invalidateRefFramesEvent;
	int lossCountSinceLastReport;
	long lastGoodFrame;
	long lastSeenFrame;
	int stopping;

	int idrFrameRequired;
	LINKED_BLOCKING_QUEUE invalidReferenceFrameTuples;

	short* packetTypes;
	short* payloadLengths;
	char** preconstructedPayloads;
} CONTROL_STREAM_CTX, *PCONTROL_STREAM_CTX;

/*static SOCKET ctlSock = INVALID_SOCKET;
static ENetHost* client;
static ENetPeer* peer;
static PLT_MUTEX enetMutex;

static PLT_THREAD lossStatsThread;
static PLT_THREAD invalidateRefFramesThread;
static PLT_EVENT invalidateRefFramesEvent;
static int lossCountSinceLastReport;
static long lastGoodFrame;
static long lastSeenFrame;
static int stopping;

static int idrFrameRequired;
static LINKED_BLOCKING_QUEUE invalidReferenceFrameTuples;*/

#define IDX_START_A 0
#define IDX_REQUEST_IDR_FRAME 0
#define IDX_START_B 1
#define IDX_INVALIDATE_REF_FRAMES 2
#define IDX_LOSS_STATS 3
#define IDX_INPUT_DATA 5

#define CONTROL_STREAM_TIMEOUT_SEC 10

static const short packetTypesGen3[] = {
    0x1407, // Request IDR frame
    0x1410, // Start B
    0x1404, // Invalidate reference frames
    0x140c, // Loss Stats
    0x1417, // Frame Stats (unused)
    -1,     // Input data (unused)
};
static const short packetTypesGen4[] = {
    0x0606, // Request IDR frame
    0x0609, // Start B
    0x0604, // Invalidate reference frames
    0x060a, // Loss Stats
    0x0611, // Frame Stats (unused)
    -1,     // Input data (unused)
};
static const short packetTypesGen5[] = {
    0x0305, // Start A
    0x0307, // Start B
    0x0301, // Invalidate reference frames
    0x0201, // Loss Stats
    0x0204, // Frame Stats (unused)
    0x0207, // Input data
};
static const short packetTypesGen7[] = {
    0x0305, // Start A
    0x0307, // Start B
    0x0301, // Invalidate reference frames
    0x0201, // Loss Stats
    0x0204, // Frame Stats (unused)
    0x0206, // Input data
};

static const char requestIdrFrameGen3[] = { 0, 0 };
static const int startBGen3[] = { 0, 0, 0, 0xa };

static const char requestIdrFrameGen4[] = { 0, 0 };
static const char startBGen4[] = { 0 };

static const char startAGen5[] = { 0, 0 };
static const char startBGen5[] = { 0 };

static const short payloadLengthsGen3[] = {
    sizeof(requestIdrFrameGen3), // Request IDR frame
    sizeof(startBGen3), // Start B
    24, // Invalidate reference frames
    32, // Loss Stats
    64, // Frame Stats
    -1, // Input data
};
static const short payloadLengthsGen4[] = {
    sizeof(requestIdrFrameGen4), // Request IDR frame
    sizeof(startBGen4), // Start B
    24, // Invalidate reference frames
    32, // Loss Stats
    64, // Frame Stats
    -1, // Input data
};
static const short payloadLengthsGen5[] = {
    sizeof(startAGen5), // Start A
    sizeof(startBGen5), // Start B
    24, // Invalidate reference frames
    32, // Loss Stats
    80, // Frame Stats
    -1, // Input data
};
static const short payloadLengthsGen7[] = {
    sizeof(startAGen5), // Start A
    sizeof(startBGen5), // Start B
    24, // Invalidate reference frames
    32, // Loss Stats
    80, // Frame Stats
    -1, // Input data
};

static const char* preconstructedPayloadsGen3[] = {
    requestIdrFrameGen3,
    (char*)startBGen3
};
static const char* preconstructedPayloadsGen4[] = {
    requestIdrFrameGen4,
    startBGen4
};
static const char* preconstructedPayloadsGen5[] = {
    startAGen5,
    startBGen5
};
static const char* preconstructedPayloadsGen7[] = {
    startAGen5,
    startBGen5
};

/*static short* packetTypes;
static short* payloadLengths;
static char**preconstructedPayloads;*/

#define LOSS_REPORT_INTERVAL_MS 50

// Initializes the control stream
int initializeControlStream(PLIMELIGHT_CTX ctx) {
	ctx->cstream = (PCONTROL_STREAM_CTX)calloc(1, sizeof(CONTROL_STREAM_CTX));
	PCONTROL_STREAM_CTX clctx = ctx->cstream;

	clctx->ctlSock = INVALID_SOCKET;
	clctx->stopping = 0;
    PltCreateEvent(&clctx->invalidateRefFramesEvent);
    LbqInitializeLinkedBlockingQueue(&clctx->invalidReferenceFrameTuples, 20);
    PltCreateMutex(&clctx->enetMutex);

    if (ctx->AppVersionQuad[0] == 3) {
		clctx->packetTypes = (short*)packetTypesGen3;
		clctx->payloadLengths = (short*)payloadLengthsGen3;
		clctx->preconstructedPayloads = (char**)preconstructedPayloadsGen3;
    }
    else if (ctx->AppVersionQuad[0] == 4) {
		clctx->packetTypes = (short*)packetTypesGen4;
		clctx->payloadLengths = (short*)payloadLengthsGen4;
		clctx->preconstructedPayloads = (char**)preconstructedPayloadsGen4;
    }
    else if (ctx->AppVersionQuad[0] == 5) {
		clctx->packetTypes = (short*)packetTypesGen5;
		clctx->payloadLengths = (short*)payloadLengthsGen5;
		clctx->preconstructedPayloads = (char**)preconstructedPayloadsGen5;
    }
    else {
		clctx->packetTypes = (short*)packetTypesGen7;
		clctx->payloadLengths = (short*)payloadLengthsGen7;
		clctx->preconstructedPayloads = (char**)preconstructedPayloadsGen7;
    }

	clctx->idrFrameRequired = 0;
	clctx->lastGoodFrame = 0;
	clctx->lastSeenFrame = 0;
	clctx->lossCountSinceLastReport = 0;

    return 0;
}

void freeFrameInvalidationList(PLINKED_BLOCKING_QUEUE_ENTRY entry) {
    PLINKED_BLOCKING_QUEUE_ENTRY nextEntry;

    while (entry != NULL) {
        nextEntry = entry->flink;
        free(entry->data);
        entry = nextEntry;
    }
}

// Cleans up control stream
void destroyControlStream(PCONTROL_STREAM_CTX clctx) {
    LC_ASSERT(clctx->stopping);
    PltCloseEvent(&clctx->invalidateRefFramesEvent);
    freeFrameInvalidationList(LbqDestroyLinkedBlockingQueue(&clctx->invalidReferenceFrameTuples));
    PltDeleteMutex(&clctx->enetMutex);
	free(clctx);
}

int getNextFrameInvalidationTuple(PCONTROL_STREAM_CTX clctx, PQUEUED_FRAME_INVALIDATION_TUPLE* qfit) {
    int err = LbqPollQueueElement(&clctx->invalidReferenceFrameTuples, (void**)qfit);
    return (err == LBQ_SUCCESS);
}

void queueFrameInvalidationTuple(PLIMELIGHT_CTX ctx, int startFrame, int endFrame) {
	PCONTROL_STREAM_CTX clctx = ctx->cstream;

    LC_ASSERT(startFrame <= endFrame);

    if (isReferenceFrameInvalidationEnabled(ctx)) {
        PQUEUED_FRAME_INVALIDATION_TUPLE qfit;
        qfit = malloc(sizeof(*qfit));
        if (qfit != NULL) {
            qfit->startFrame = startFrame;
            qfit->endFrame = endFrame;
            if (LbqOfferQueueItem(&clctx->invalidReferenceFrameTuples, qfit, &qfit->entry) == LBQ_BOUND_EXCEEDED) {
                // Too many invalidation tuples, so we need an IDR frame now
                free(qfit);
				clctx->idrFrameRequired = 1;
            }
        }
        else {
			clctx->idrFrameRequired = 1;
        }
    }
    else {
		clctx->idrFrameRequired = 1;
    }

    PltSetEvent(&clctx->invalidateRefFramesEvent);
}

// Request an IDR frame on demand by the decoder
void requestIdrOnDemand(PCONTROL_STREAM_CTX clctx) {
	clctx->idrFrameRequired = 1;
    PltSetEvent(&clctx->invalidateRefFramesEvent);
}

// Invalidate reference frames lost by the network
void connectionDetectedFrameLoss(PLIMELIGHT_CTX ctx, int startFrame, int endFrame) {
    queueFrameInvalidationTuple(ctx, startFrame, endFrame);
}

// When we receive a frame, update the number of our current frame
void connectionReceivedCompleteFrame(PCONTROL_STREAM_CTX clctx, int frameIndex) {
	clctx->lastGoodFrame = frameIndex;
}

void connectionSawFrame(PCONTROL_STREAM_CTX clctx, int frameIndex) {
	clctx->lastSeenFrame = frameIndex;
}

// When we lose packets, update our packet loss count
void connectionLostPackets(PCONTROL_STREAM_CTX clctx, int lastReceivedPacket, int nextReceivedPacket) {
	clctx->lossCountSinceLastReport += (nextReceivedPacket - lastReceivedPacket) - 1;
}

// Reads an NV control stream packet from the TCP connection
static PNVCTL_TCP_PACKET_HEADER readNvctlPacketTcp(PCONTROL_STREAM_CTX clctx) {
    NVCTL_TCP_PACKET_HEADER staticHeader;
    PNVCTL_TCP_PACKET_HEADER fullPacket;
    SOCK_RET err;

    err = recv(clctx->ctlSock, (char*)&staticHeader, sizeof(staticHeader), 0);
    if (err != sizeof(staticHeader)) {
        return NULL;
    }

    fullPacket = (PNVCTL_TCP_PACKET_HEADER)malloc(staticHeader.payloadLength + sizeof(staticHeader));
    if (fullPacket == NULL) {
        return NULL;
    }

    memcpy(fullPacket, &staticHeader, sizeof(staticHeader));
    if (staticHeader.payloadLength != 0) {
        err = recv(clctx->ctlSock, (char*)(fullPacket + 1), staticHeader.payloadLength, 0);
        if (err != staticHeader.payloadLength) {
            free(fullPacket);
            return NULL;
        }
    }

    return fullPacket;
}

static int sendMessageEnet(PLIMELIGHT_CTX ctx, short ptype, short paylen, const void* payload) {
	PCONTROL_STREAM_CTX clctx = ctx->cstream;

    PNVCTL_ENET_PACKET_HEADER packet;
    ENetPacket* enetPacket;
    ENetEvent event;
    int err;

    LC_ASSERT(ctx->AppVersionQuad[0] >= 5);

    // Gen 5+ servers do control protocol over ENet instead of TCP
    while ((err = serviceEnetHost(ctx, clctx->client, &event, 0)) > 0) {
        if (event.type == ENET_EVENT_TYPE_RECEIVE) {
            enet_packet_destroy(event.packet);
        }
        else if (event.type == ENET_EVENT_TYPE_DISCONNECT) {
            Limelog("Control stream received disconnect event\n");
            return 0;
        }
    }

    if (err < 0) {
        Limelog("Control stream connection failed\n");
        return 0;
    }

    packet = malloc(sizeof(*packet) + paylen);
    if (packet == NULL) {
        return 0;
    }

    packet->type = ptype;
    memcpy(&packet[1], payload, paylen);

    enetPacket = enet_packet_create(packet, sizeof(*packet) + paylen, ENET_PACKET_FLAG_RELIABLE);
    if (enetPacket == NULL) {
        free(packet);
        return 0;
    }

    if (enet_peer_send(clctx->peer, 0, enetPacket) < 0) {
        Limelog("Failed to send ENet control packet\n");
        enet_packet_destroy(enetPacket);
        free(packet);
        return 0;
    }

    enet_host_flush(clctx->client);

    free(packet);

    return 1;
}

static int sendMessageTcp(PLIMELIGHT_CTX ctx, short ptype, short paylen, const void* payload) {
    PNVCTL_TCP_PACKET_HEADER packet;
    SOCK_RET err;

    LC_ASSERT(ctx->AppVersionQuad[0] < 5);

    packet = malloc(sizeof(*packet) + paylen);
    if (packet == NULL) {
        return 0;
    }

    packet->type = ptype;
    packet->payloadLength = paylen;
    memcpy(&packet[1], payload, paylen);

    err = send(ctx->cstream->ctlSock, (char*) packet, sizeof(*packet) + paylen, 0);
    free(packet);

    if (err != sizeof(*packet) + paylen) {
        return 0;
    }

    return 1;
}

static int sendMessageAndForget(PLIMELIGHT_CTX ctx, short ptype, short paylen, const void* payload) {
    int ret;

    // Unlike regular sockets, ENet sockets aren't safe to invoke from multiple
    // threads at once. We have to synchronize them with a lock.
    if (ctx->AppVersionQuad[0] >= 5) {
        PltLockMutex(&ctx->cstream->enetMutex);
        ret = sendMessageEnet(ctx, ptype, paylen, payload);
        PltUnlockMutex(&ctx->cstream->enetMutex);
    }
    else {
        ret = sendMessageTcp(ctx, ptype, paylen, payload);
    }

    return ret;
}

static int sendMessageAndDiscardReply(PLIMELIGHT_CTX ctx, short ptype, short paylen, const void* payload) {
    if (ctx->AppVersionQuad[0] >= 5) {
        PltLockMutex(&ctx->cstream->enetMutex);

        if (!sendMessageEnet(ctx, ptype, paylen, payload)) {
            PltUnlockMutex(&ctx->cstream->enetMutex);
            return 0;
        }

        PltUnlockMutex(&ctx->cstream->enetMutex);
    }
    else {
        PNVCTL_TCP_PACKET_HEADER reply;

        if (!sendMessageTcp(ctx, ptype, paylen, payload)) {
            return 0;
        }

        reply = readNvctlPacketTcp(ctx->cstream);
        if (reply == NULL) {
            return 0;
        }

        free(reply);
    }

    return 1;
}

static void lossStatsThreadFunc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;
	PCONTROL_STREAM_CTX clctx = ctx->cstream;

    char*lossStatsPayload;
    BYTE_BUFFER byteBuffer;

    lossStatsPayload = malloc(ctx->cstream->payloadLengths[IDX_LOSS_STATS]);
    if (lossStatsPayload == NULL) {
        Limelog("Loss Stats: malloc() failed\n");
        ctx->connectionTerminatedInternal(ctx, -1);
        return;
    }

    while (!PltIsThreadInterrupted(&clctx->lossStatsThread)) {
        // Construct the payload
        BbInitializeWrappedBuffer(&byteBuffer, lossStatsPayload, 0, clctx->payloadLengths[IDX_LOSS_STATS], BYTE_ORDER_LITTLE);
        BbPutInt(&byteBuffer, clctx->lossCountSinceLastReport);
        BbPutInt(&byteBuffer, LOSS_REPORT_INTERVAL_MS);
        BbPutInt(&byteBuffer, 1000);
        BbPutLong(&byteBuffer, clctx->lastGoodFrame);
        BbPutInt(&byteBuffer, 0);
        BbPutInt(&byteBuffer, 0);
        BbPutInt(&byteBuffer, 0x14);

        // Send the message (and don't expect a response)
        if (!sendMessageAndForget(ctx, clctx->packetTypes[IDX_LOSS_STATS],
								  clctx->payloadLengths[IDX_LOSS_STATS], lossStatsPayload)) {
            free(lossStatsPayload);
            Limelog("Loss Stats: Transaction failed: %d\n", (int)LastSocketError());
            ctx->connectionTerminatedInternal(ctx, LastSocketError());
            return;
        }

        // Clear the transient state
		clctx->lossCountSinceLastReport = 0;

        // Wait a bit
        PltSleepMs(LOSS_REPORT_INTERVAL_MS);
    }

    free(lossStatsPayload);
}

static void requestIdrFrame(PLIMELIGHT_CTX ctx) {
	PCONTROL_STREAM_CTX clctx = ctx->cstream;

    long long payload[3];

    if (ctx->AppVersionQuad[0] >= 5) {
        // Form the payload
        if (clctx->lastSeenFrame < 0x20) {
            payload[0] = 0;
            payload[1] = 0x20;
        }
        else {
            payload[0] = ctx->cstream->lastSeenFrame - 0x20;
            payload[1] = ctx->cstream->lastSeenFrame;
        }

        payload[2] = 0;

        // Send the reference frame invalidation request and read the response
        if (!sendMessageAndDiscardReply(ctx, clctx->packetTypes[IDX_INVALIDATE_REF_FRAMES],
										clctx->payloadLengths[IDX_INVALIDATE_REF_FRAMES], payload)) {
            Limelog("Request IDR Frame: Transaction failed: %d\n", (int)LastSocketError());
            ctx->connectionTerminatedInternal(ctx, LastSocketError());
            return;
        }
    }
    else {
        // Send IDR frame request and read the response
        if (!sendMessageAndDiscardReply(ctx, clctx->packetTypes[IDX_REQUEST_IDR_FRAME],
										clctx->payloadLengths[IDX_REQUEST_IDR_FRAME], clctx->preconstructedPayloads[IDX_REQUEST_IDR_FRAME])) {
            Limelog("Request IDR Frame: Transaction failed: %d\n", (int)LastSocketError());
			ctx->connectionTerminatedInternal(ctx, LastSocketError());
            return;
        }
    }

    Limelog("IDR frame request sent\n");
}

static void requestInvalidateReferenceFrames(PLIMELIGHT_CTX ctx) {
	PCONTROL_STREAM_CTX clctx = ctx->cstream;

    long long payload[3];
    PQUEUED_FRAME_INVALIDATION_TUPLE qfit;

    LC_ASSERT(isReferenceFrameInvalidationEnabled());

    if (!getNextFrameInvalidationTuple(clctx, &qfit)) {
        return;
    }

    LC_ASSERT(qfit->startFrame <= qfit->endFrame);

    payload[0] = qfit->startFrame;
    payload[1] = qfit->endFrame;
    payload[2] = 0;

    // Aggregate all lost frames into one range
    do {
        LC_ASSERT(qfit->endFrame >= payload[1]);
        payload[1] = qfit->endFrame;
        free(qfit);
    } while (getNextFrameInvalidationTuple(clctx, &qfit));

    // Send the reference frame invalidation request and read the response
    if (!sendMessageAndDiscardReply(ctx, clctx->packetTypes[IDX_INVALIDATE_REF_FRAMES],
									clctx->payloadLengths[IDX_INVALIDATE_REF_FRAMES], payload)) {
        Limelog("Request Invaldiate Reference Frames: Transaction failed: %d\n", (int)LastSocketError());
        ctx->connectionTerminatedInternal(ctx, LastSocketError());
        return;
    }

    Limelog("Invalidate reference frame request sent (%d to %d)\n", (int)payload[0], (int)payload[1]);
}

static void invalidateRefFramesFunc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;
	PCONTROL_STREAM_CTX clctx = ctx->cstream;

    while (!PltIsThreadInterrupted(&clctx->invalidateRefFramesThread)) {
        // Wait for a request to invalidate reference frames
        PltWaitForEvent(&clctx->invalidateRefFramesEvent);
        PltClearEvent(&clctx->invalidateRefFramesEvent);

        // Bail if we've been shutdown
        if (clctx->stopping) {
            break;
        }

        // Sometimes we absolutely need an IDR frame
        if (clctx->idrFrameRequired) {
            // Empty invalidate reference frames tuples
            PQUEUED_FRAME_INVALIDATION_TUPLE qfit;
            while (getNextFrameInvalidationTuple(clctx, &qfit)) {
                free(qfit);
            }

            // Send an IDR frame request
			clctx->idrFrameRequired = 0;
            requestIdrFrame(ctx);
        }
        else {
            // Otherwise invalidate reference frames
            requestInvalidateReferenceFrames(ctx);
        }
    }
}

// Stops the control stream
int stopControlStream(PLIMELIGHT_CTX ctx) {
	PCONTROL_STREAM_CTX clctx = ctx->cstream;

	clctx->stopping = 1;
    LbqSignalQueueShutdown(&clctx->invalidReferenceFrameTuples);
    PltSetEvent(&clctx->invalidateRefFramesEvent);

    // This must be set to stop in a timely manner
    LC_ASSERT(ctx->ConnectionInterrupted);

    if (clctx->ctlSock != INVALID_SOCKET) {
        shutdownTcpSocket(clctx->ctlSock);
    }

    PltInterruptThread(&clctx->lossStatsThread);
    PltInterruptThread(&clctx->invalidateRefFramesThread);

    PltJoinThread(&clctx->lossStatsThread);
    PltJoinThread(&clctx->invalidateRefFramesThread);

    PltCloseThread(&clctx->lossStatsThread);
    PltCloseThread(&clctx->invalidateRefFramesThread);

    if (clctx->peer != NULL) {
        // We use enet_peer_disconnect_now() so the host knows immediately
        // of our termination and can cleanup properly for reconnection.
        enet_peer_disconnect_now(clctx->peer, 0);
		clctx->peer = NULL;
    }
    if (clctx->client != NULL) {
        enet_host_destroy(clctx->client);
		clctx->client = NULL;
    }

    if (clctx->ctlSock != INVALID_SOCKET) {
        closeSocket(clctx->ctlSock);
		clctx->ctlSock = INVALID_SOCKET;
    }

    return 0;
}

// Called by the input stream to send a packet for Gen 5+ servers
int sendInputPacketOnControlStream(PLIMELIGHT_CTX ctx, unsigned char* data, int length) {
    LC_ASSERT(ctx->AppVersionQuad[0] >= 5);

    // Send the input data (no reply expected)
    if (sendMessageAndForget(ctx, ctx->cstream->packetTypes[IDX_INPUT_DATA], length, data) == 0) {
        return -1;
    }

    return 0;
}

// Starts the control stream
int startControlStream(PLIMELIGHT_CTX ctx) {
	PCONTROL_STREAM_CTX clctx = ctx->cstream;

    int err;

    if (ctx->AppVersionQuad[0] >= 5) {
        ENetAddress address;
        ENetEvent event;

        enet_address_set_address(&address, (struct sockaddr *)&ctx->RemoteAddr, ctx->RemoteAddrLen);
        enet_address_set_port(&address, 47999);

        // Create a client that can use 1 outgoing connection and 1 channel
		clctx->client = enet_host_create(address.address.ss_family, NULL, 1, 1, 0, 0);
        if (clctx->client == NULL) {
            return -1;
        }

        // Connect to the host
		clctx->peer = enet_host_connect(clctx->client, &address, 1, 0);
        if (clctx->peer == NULL) {
            enet_host_destroy(clctx->client);
			clctx->client = NULL;
            return -1;
        }

        // Wait for the connect to complete
        if (serviceEnetHost(ctx, clctx->client, &event, CONTROL_STREAM_TIMEOUT_SEC * 1000) <= 0 ||
            event.type != ENET_EVENT_TYPE_CONNECT) {
            Limelog("RTSP: Failed to connect to UDP port 47999\n");
            enet_peer_reset(clctx->peer);
			clctx->peer = NULL;
            enet_host_destroy(clctx->client);
			clctx->client = NULL;
            return -1;
        }

        // Ensure the connect verify ACK is sent immediately
        enet_host_flush(clctx->client);

        // Set the max peer timeout to 10 seconds
        enet_peer_timeout(clctx->peer, ENET_PEER_TIMEOUT_LIMIT, ENET_PEER_TIMEOUT_MINIMUM, 10000);
    }
    else {
		clctx->ctlSock = connectTcpSocket(ctx, &ctx->RemoteAddr, ctx->RemoteAddrLen,
            47995, CONTROL_STREAM_TIMEOUT_SEC);
        if (clctx->ctlSock == INVALID_SOCKET) {
            return LastSocketFail();
        }

        enableNoDelay(clctx->ctlSock);
    }

    // Send START A
    if (!sendMessageAndDiscardReply(ctx, clctx->packetTypes[IDX_START_A],
									clctx->payloadLengths[IDX_START_A],
									clctx->preconstructedPayloads[IDX_START_A])) {
        Limelog("Start A failed: %d\n", (int)LastSocketError());
        err = LastSocketFail();
		clctx->stopping = 1;
        if (clctx->ctlSock != INVALID_SOCKET) {
            closeSocket(clctx->ctlSock);
			clctx->ctlSock = INVALID_SOCKET;
        }
        else {
            enet_peer_disconnect_now(clctx->peer, 0);
			clctx->peer = NULL;
            enet_host_destroy(clctx->client);
			clctx->client = NULL;
        }
        return err;
    }

    // Send START B
    if (!sendMessageAndDiscardReply(ctx, clctx->packetTypes[IDX_START_B],
									clctx->payloadLengths[IDX_START_B],
									clctx->preconstructedPayloads[IDX_START_B])) {
        Limelog("Start B failed: %d\n", (int)LastSocketError());
        err = LastSocketFail();
		clctx->stopping = 1;
        if (clctx->ctlSock != INVALID_SOCKET) {
            closeSocket(clctx->ctlSock);
			clctx->ctlSock = INVALID_SOCKET;
        }
        else {
            enet_peer_disconnect_now(clctx->peer, 0);
			clctx->peer = NULL;
            enet_host_destroy(clctx->client);
			clctx->client = NULL;
        }
        return err;
    }

    err = PltCreateThread(lossStatsThreadFunc, ctx, &clctx->lossStatsThread);
    if (err != 0) {
		clctx->stopping = 1;
        if (clctx->ctlSock != INVALID_SOCKET) {
            closeSocket(clctx->ctlSock);
			clctx->ctlSock = INVALID_SOCKET;
        }
        else {
            enet_peer_disconnect_now(clctx->peer, 0);
            clctx->peer = NULL;
            enet_host_destroy(clctx->client);
            clctx->client = NULL;
        }
        return err;
    }

    err = PltCreateThread(invalidateRefFramesFunc, ctx, &clctx->invalidateRefFramesThread);
    if (err != 0) {
		clctx->stopping = 1;

        if (clctx->ctlSock != INVALID_SOCKET) {
            shutdownTcpSocket(clctx->ctlSock);
        }
        else {
            ctx->ConnectionInterrupted = 1;
        }

        PltInterruptThread(&clctx->lossStatsThread);
        PltJoinThread(&clctx->lossStatsThread);
        PltCloseThread(&clctx->lossStatsThread);

        if (clctx->ctlSock != INVALID_SOCKET) {
            closeSocket(clctx->ctlSock);
			clctx->ctlSock = INVALID_SOCKET;
        }
        else {
            enet_peer_disconnect_now(clctx->peer, 0);
            clctx->peer = NULL;
            enet_host_destroy(clctx->client);
            clctx->client = NULL;
        }

        return err;
    }

    return 0;
}
