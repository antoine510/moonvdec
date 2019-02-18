#include "Limelight-internal.h"
#include "Rtsp.h"

#include <enet/enet.h>

#define RTSP_MAX_RESP_SIZE 32768
#define RTSP_TIMEOUT_SEC 10

typedef struct _RTSP_CONNECTION_CTX {
	int currentSeqNumber;
	char rtspTargetUrl[256];
	char sessionIdString[16];
	int hasSessionId;
	char responseBuffer[RTSP_MAX_RESP_SIZE];
	int rtspClientVersion;
	char urlAddr[URLSAFESTRING_LEN];
	int useEnet;

	SOCKET sock;
	ENetHost* client;
	ENetPeer* peer;
} RTSP_CONNECTION_CTX, *PRTSP_CONNECTION_CTX;

/*static int currentSeqNumber;
static char rtspTargetUrl[256];
static char sessionIdString[16];
static int hasSessionId;
static char responseBuffer[RTSP_MAX_RESP_SIZE];
static int rtspClientVersion;
static char urlAddr[URLSAFESTRING_LEN];
static int useEnet;

static SOCKET sock = INVALID_SOCKET;
static ENetHost* client;
static ENetPeer* peer;*/

// Create RTSP Option
static POPTION_ITEM createOptionItem(char* option, char* content)
{
    POPTION_ITEM item = malloc(sizeof(*item));
    if (item == NULL) {
        return NULL;
    }

    item->option = malloc(strlen(option) + 1);
    if (item->option == NULL) {
        free(item);
        return NULL;
    }

    strcpy(item->option, option);

    item->content = malloc(strlen(content) + 1);
    if (item->content == NULL) {
        free(item->option);
        free(item);
        return NULL;
    }

    strcpy(item->content, content);

    item->next = NULL;
    item->flags = FLAG_ALLOCATED_OPTION_FIELDS;

    return item;
}

// Add an option to the RTSP Message
static int addOption(PRTSP_MESSAGE msg, char* option, char* content)
{
    POPTION_ITEM item = createOptionItem(option, content);
    if (item == NULL) {
        return 0;
    }

    insertOption(&msg->options, item);
    msg->flags |= FLAG_ALLOCATED_OPTION_ITEMS;

    return 1;
}

// Create an RTSP Request
static int initializeRtspRequest(PRTSP_CONNECTION_CTX rctx, PRTSP_MESSAGE msg, char* command, char* target)
{
    char sequenceNumberStr[16];
    char clientVersionStr[16];

    // FIXME: Hacked CSeq attribute due to RTSP parser bug
    createRtspRequest(msg, NULL, 0, command, target, "RTSP/1.0",
        0, NULL, NULL, 0);

    sprintf(sequenceNumberStr, "%d", rctx->currentSeqNumber++);
    sprintf(clientVersionStr, "%d", rctx->rtspClientVersion);
    if (!addOption(msg, "CSeq", sequenceNumberStr) ||
        !addOption(msg, "X-GS-ClientVersion", clientVersionStr) ||
        (!rctx->useEnet && !addOption(msg, "Host", rctx->urlAddr))) {
        freeMessage(msg);
        return 0;
    }

    return 1;
}

// Send RTSP message and get response over ENet
static int transactRtspMessageEnet(PLIMELIGHT_CTX ctx, PRTSP_MESSAGE request, PRTSP_MESSAGE response, int expectingPayload, int* error) {
	PRTSP_CONNECTION_CTX rctx = ctx->rtsp;

	ENetEvent event;
    char* serializedMessage;
    int messageLen;
    int offset;
    ENetPacket* packet;
    char* payload;
    int payloadLength;
    int ret;

    // We're going to handle the payload separately, so temporarily set the payload to NULL
    payload = request->payload;
    payloadLength = request->payloadLength;
    request->payload = NULL;
    request->payloadLength = 0;

    // Serialize the RTSP message into a message buffer
    serializedMessage = serializeRtspMessage(request, &messageLen);
    if (serializedMessage == NULL) {
        ret = 0;
        goto Exit;
    }

    // Create the reliable packet that describes our outgoing message
    packet = enet_packet_create(serializedMessage, messageLen, ENET_PACKET_FLAG_RELIABLE);
    if (packet == NULL) {
        ret = 0;
        goto Exit;
    }

    // Send the message
    if (enet_peer_send(rctx->peer, 0, packet) < 0) {
        enet_packet_destroy(packet);
        ret = 0;
        goto Exit;
    }
    enet_host_flush(rctx->client);

    // If we have a payload to send, we'll need to send that separately
    if (payload != NULL) {
        packet = enet_packet_create(payload, payloadLength, ENET_PACKET_FLAG_RELIABLE);
        if (packet == NULL) {
            ret = 0;
            goto Exit;
        }

        // Send the payload
        if (enet_peer_send(rctx->peer, 0, packet) < 0) {
            enet_packet_destroy(packet);
            ret = 0;
            goto Exit;
        }

        enet_host_flush(rctx->client);
    }

    // Wait for a reply
    if (serviceEnetHost(ctx, rctx->client, &event, RTSP_TIMEOUT_SEC * 1000) <= 0 ||
        event.type != ENET_EVENT_TYPE_RECEIVE) {
        Limelog("Failed to receive RTSP reply\n");
        ret = 0;
        goto Exit;
    }

    if (event.packet->dataLength > RTSP_MAX_RESP_SIZE) {
        Limelog("RTSP message too long\n");
        ret = 0;
        goto Exit;
    }

    // Copy the data out and destroy the packet
    memcpy(rctx->responseBuffer, event.packet->data, event.packet->dataLength);
    offset = (int) event.packet->dataLength;
    enet_packet_destroy(event.packet);

    // Wait for the payload if we're expecting some
    if (expectingPayload) {
        // The payload comes in a second packet
        if (serviceEnetHost(ctx, rctx->client, &event, RTSP_TIMEOUT_SEC * 1000) <= 0 ||
            event.type != ENET_EVENT_TYPE_RECEIVE) {
            Limelog("Failed to receive RTSP reply payload\n");
            ret = 0;
            goto Exit;
        }

        if (event.packet->dataLength + offset > RTSP_MAX_RESP_SIZE) {
            Limelog("RTSP message payload too long\n");
            ret = 0;
            goto Exit;
        }

        // Copy the payload out to the end of the response buffer and destroy the packet
        memcpy(&rctx->responseBuffer[offset], event.packet->data, event.packet->dataLength);
        offset += (int) event.packet->dataLength;
        enet_packet_destroy(event.packet);
    }

    if (parseRtspMessage(response, rctx->responseBuffer, offset) == RTSP_ERROR_SUCCESS) {
        // Successfully parsed response
        ret = 1;
    }
    else {
        Limelog("Failed to parse RTSP response\n");
        ret = 0;
    }

Exit:
    // Swap back the payload pointer to avoid leaking memory later
    request->payload = payload;
    request->payloadLength = payloadLength;

    // Free the serialized buffer
    if (serializedMessage != NULL) {
        free(serializedMessage);
    }

    return ret;
}

// Send RTSP message and get response over TCP
static int transactRtspMessageTcp(PLIMELIGHT_CTX ctx, PRTSP_MESSAGE request, PRTSP_MESSAGE response, int expectingPayload, int* error) {
	PRTSP_CONNECTION_CTX rctx = ctx->rtsp;

	SOCK_RET err;
    int ret = 0;
    int offset;
    char* serializedMessage = NULL;
    int messageLen;

    *error = -1;

	rctx->sock = connectTcpSocket(ctx, &ctx->RemoteAddr, ctx->RemoteAddrLen, 48010, RTSP_TIMEOUT_SEC);
    if (rctx->sock == INVALID_SOCKET) {
        *error = LastSocketError();
        return ret;
    }
    enableNoDelay(rctx->sock);
    setRecvTimeout(ctx, rctx->sock, RTSP_TIMEOUT_SEC);

    serializedMessage = serializeRtspMessage(request, &messageLen);
    if (serializedMessage == NULL) {
        closeSocket(rctx->sock);
		rctx->sock = INVALID_SOCKET;
        return ret;
    }

    // Send our message
    err = send(rctx->sock, serializedMessage, messageLen, 0);
    if (err == SOCKET_ERROR) {
        *error = LastSocketError();
        Limelog("Failed to send RTSP message: %d\n", *error);
        goto Exit;
    }

    // Read the response until the server closes the connection
    offset = 0;
    for (;;) {
        err = recv(rctx->sock, &rctx->responseBuffer[offset], RTSP_MAX_RESP_SIZE - offset, 0);
        if (err <= 0) {
            // Done reading
            break;
        }
        offset += err;

        // Warn if the RTSP message is too big
        if (offset == RTSP_MAX_RESP_SIZE) {
            Limelog("RTSP message too long\n");
            goto Exit;
        }
    }

    if (parseRtspMessage(response, rctx->responseBuffer, offset) == RTSP_ERROR_SUCCESS) {
        // Successfully parsed response
        ret = 1;
    }
    else {
        Limelog("Failed to parse RTSP response\n");
    }

Exit:
    if (serializedMessage != NULL) {
        free(serializedMessage);
    }

    closeSocket(rctx->sock);
	rctx->sock = INVALID_SOCKET;
    return ret;
}

static int transactRtspMessage(PLIMELIGHT_CTX ctx, PRTSP_MESSAGE request, PRTSP_MESSAGE response, int expectingPayload, int* error) {
    if (ctx->rtsp->useEnet) {
        return transactRtspMessageEnet(ctx, request, response, expectingPayload, error);
    }
    else {
        return transactRtspMessageTcp(ctx, request, response, expectingPayload, error);
    }
}

// Send RTSP OPTIONS request
static int requestOptions(PLIMELIGHT_CTX ctx, PRTSP_MESSAGE response, int* error) {
    RTSP_MESSAGE request;
    int ret;

    *error = -1;

    ret = initializeRtspRequest(ctx->rtsp, &request, "OPTIONS", ctx->rtsp->rtspTargetUrl);
    if (ret != 0) {
        ret = transactRtspMessage(ctx, &request, response, 0, error);
        freeMessage(&request);
    }

    return ret;
}

// Send RTSP DESCRIBE request
static int requestDescribe(PLIMELIGHT_CTX ctx, PRTSP_MESSAGE response, int* error) {
    RTSP_MESSAGE request;
    int ret;

    *error = -1;

    ret = initializeRtspRequest(ctx->rtsp, &request, "DESCRIBE", ctx->rtsp->rtspTargetUrl);
    if (ret != 0) {
        if (addOption(&request, "Accept",
            "application/sdp") &&
            addOption(&request, "If-Modified-Since",
                "Thu, 01 Jan 1970 00:00:00 GMT")) {
            ret = transactRtspMessage(ctx, &request, response, 1, error);
        }
        else {
            ret = 0;
        }
        freeMessage(&request);
    }

    return ret;
}

// Send RTSP SETUP request
static int setupStream(PLIMELIGHT_CTX ctx, PRTSP_MESSAGE response, char* target, int* error) {
    RTSP_MESSAGE request;
    int ret;
    char* transportValue;

    *error = -1;

    ret = initializeRtspRequest(ctx->rtsp, &request, "SETUP", target);
    if (ret != 0) {
        if (ctx->rtsp->hasSessionId) {
            if (!addOption(&request, "Session", ctx->rtsp->sessionIdString)) {
                ret = 0;
                goto FreeMessage;
            }
        }

        if (ctx->AppVersionQuad[0] >= 6) {
            // It looks like GFE doesn't care what we say our port is but
            // we need to give it some port to successfully complete the
            // handshake process.
            transportValue = "unicast;X-GS-ClientPort=50000-50001";
        }
        else {
            transportValue = " ";
        }

        if (addOption(&request, "Transport", transportValue) &&
            addOption(&request, "If-Modified-Since",
                "Thu, 01 Jan 1970 00:00:00 GMT")) {
            ret = transactRtspMessage(ctx, &request, response, 0, error);
        }
        else {
            ret = 0;
        }

    FreeMessage:
        freeMessage(&request);
    }

    return ret;
}

// Send RTSP PLAY request
static int playStream(PLIMELIGHT_CTX ctx, PRTSP_MESSAGE response, char* target, int* error) {
    RTSP_MESSAGE request;
    int ret;

    *error = -1;

    ret = initializeRtspRequest(ctx->rtsp, &request, "PLAY", target);
    if (ret != 0) {
        if (addOption(&request, "Session", ctx->rtsp->sessionIdString)) {
            ret = transactRtspMessage(ctx, &request, response, 0, error);
        }
        else {
            ret = 0;
        }
        freeMessage(&request);
    }

    return ret;
}

// Send RTSP ANNOUNCE message
static int sendVideoAnnounce(PLIMELIGHT_CTX ctx, PRTSP_MESSAGE response, int* error) {
    RTSP_MESSAGE request;
    int ret;
    int payloadLength;
    char payloadLengthStr[16];

    *error = -1;

    ret = initializeRtspRequest(ctx->rtsp, &request, "ANNOUNCE", "streamid=video");
    if (ret != 0) {
        ret = 0;

        if (!addOption(&request, "Session", ctx->rtsp->sessionIdString) ||
            !addOption(&request, "Content-type", "application/sdp")) {
            goto FreeMessage;
        }

        request.payload = getSdpPayloadForStreamConfig(ctx, ctx->rtsp->rtspClientVersion, &payloadLength);
        if (request.payload == NULL) {
            goto FreeMessage;
        }
        request.flags |= FLAG_ALLOCATED_PAYLOAD;
        request.payloadLength = payloadLength;

        sprintf(payloadLengthStr, "%d", payloadLength);
        if (!addOption(&request, "Content-length", payloadLengthStr)) {
            goto FreeMessage;
        }

        ret = transactRtspMessage(ctx, &request, response, 0, error);

    FreeMessage:
        freeMessage(&request);
    }

    return ret;
}

// Frees up RTSP connection state
void destroyRtspConnection(PRTSP_CONNECTION_CTX rctx) {
	free(rctx);
}

// Perform RTSP Handshake with the streaming server machine as part of the connection process
int performRtspHandshake(PLIMELIGHT_CTX ctx) {
	ctx->rtsp = (PRTSP_CONNECTION_CTX)calloc(1, sizeof(RTSP_CONNECTION_CTX));
	PRTSP_CONNECTION_CTX rctx = ctx->rtsp;

    int ret;

    // Initialize global state
	rctx->sock = INVALID_SOCKET;
	rctx->useEnet = (ctx->AppVersionQuad[0] >= 5) && (ctx->AppVersionQuad[0] <= 7) && (ctx->AppVersionQuad[2] < 404);
    addrToUrlSafeString(&ctx->RemoteAddr, rctx->urlAddr);
    sprintf(rctx->rtspTargetUrl, "rtsp%s://%s:48010", rctx->useEnet ? "ru" : "", rctx->urlAddr);
	rctx->currentSeqNumber = 1;
	rctx->hasSessionId = 0;

    switch (ctx->AppVersionQuad[0]) {
        case 3:
			rctx->rtspClientVersion = 10;
            break;
        case 4:
			rctx->rtspClientVersion = 11;
            break;
        case 5:
			rctx->rtspClientVersion = 12;
            break;
        case 6:
            // Gen 6 has never been seen in the wild
			rctx->rtspClientVersion = 13;
            break;
        case 7:
        default:
			rctx->rtspClientVersion = 14;
            break;
    }

    // Setup ENet if required by this GFE version
    if (rctx->useEnet) {
        ENetAddress address;
        ENetEvent event;

        enet_address_set_address(&address, (struct sockaddr *)&ctx->RemoteAddr, ctx->RemoteAddrLen);
        enet_address_set_port(&address, 48010);

        // Create a client that can use 1 outgoing connection and 1 channel
		rctx->client = enet_host_create(ctx->RemoteAddr.ss_family, NULL, 1, 1, 0, 0);
        if (rctx->client == NULL) {
            return -1;
        }

        // Connect to the host
		rctx->peer = enet_host_connect(rctx->client, &address, 1, 0);
        if (rctx->peer == NULL) {
            enet_host_destroy(rctx->client);
			rctx->client = NULL;
            return -1;
        }

        // Wait for the connect to complete
        if (serviceEnetHost(ctx, rctx->client, &event, RTSP_TIMEOUT_SEC * 1000) <= 0 ||
            event.type != ENET_EVENT_TYPE_CONNECT) {
            Limelog("RTSP: Failed to connect to UDP port 48010\n");
            enet_peer_reset(rctx->peer);
			rctx->peer = NULL;
            enet_host_destroy(rctx->client);
			rctx->client = NULL;
            return -1;
        }

        // Ensure the connect verify ACK is sent immediately
        enet_host_flush(rctx->client);
    }

    {
        RTSP_MESSAGE response;
        int error = -1;

        if (!requestOptions(ctx, &response, &error)) {
            Limelog("RTSP OPTIONS request failed: %d\n", error);
            ret = error;
            goto Exit;
        }

        if (response.message.response.statusCode != 200) {
            Limelog("RTSP OPTIONS request failed: %d\n",
                response.message.response.statusCode);
            ret = response.message.response.statusCode;
            goto Exit;
        }

        freeMessage(&response);
    }

    {
        RTSP_MESSAGE response;
        int error = -1;

        if (!requestDescribe(ctx, &response, &error)) {
            Limelog("RTSP DESCRIBE request failed: %d\n", error);
            ret = error;
            goto Exit;
        }

        if (response.message.response.statusCode != 200) {
            Limelog("RTSP DESCRIBE request failed: %d\n",
                response.message.response.statusCode);
            ret = response.message.response.statusCode;
            goto Exit;
        }

        // The RTSP DESCRIBE reply will contain a collection of SDP media attributes that
        // describe the various supported video stream formats and include the SPS, PPS,
        // and VPS (if applicable). We will use this information to determine whether the
        // server can support HEVC. For some reason, they still set the MIME type of the HEVC
        // format to H264, so we can't just look for the HEVC MIME type. What we'll do instead is
        // look for the base 64 encoded VPS NALU prefix that is unique to the HEVC bitstream.
        if (ctx->StreamConfig.supportsHevc && strstr(response.payload, "sprop-parameter-sets=AAAAAU")) {
            if (ctx->StreamConfig.enableHdr) {
				ctx->NegotiatedVideoFormat = VIDEO_FORMAT_H265_MAIN10;
            }
            else {
				ctx->NegotiatedVideoFormat = VIDEO_FORMAT_H265;

                // Apply bitrate adjustment for SDR HEVC if the client requested one
                if (ctx->StreamConfig.hevcBitratePercentageMultiplier != 0) {
					ctx->StreamConfig.bitrate *= ctx->StreamConfig.hevcBitratePercentageMultiplier;
					ctx->StreamConfig.bitrate /= 100;
                }
            }
        }
        else {
			ctx->NegotiatedVideoFormat = VIDEO_FORMAT_H264;
        }

        freeMessage(&response);
    }

    {
        RTSP_MESSAGE response;
        char* sessionId;
        int error = -1;

        if (!setupStream(ctx, &response,
						 ctx->AppVersionQuad[0] >= 5 ? "streamid=audio/0/0" : "streamid=audio",
                         &error)) {
            Limelog("RTSP SETUP streamid=audio request failed: %d\n", error);
            ret = error;
            goto Exit;
        }

        if (response.message.response.statusCode != 200) {
            Limelog("RTSP SETUP streamid=audio request failed: %d\n",
                response.message.response.statusCode);
            ret = response.message.response.statusCode;
            goto Exit;
        }

        sessionId = getOptionContent(response.options, "Session");
        if (sessionId == NULL) {
            Limelog("RTSP SETUP streamid=audio is missing session attribute");
            ret = -1;
            goto Exit;
        }

        strcpy(rctx->sessionIdString, sessionId);
		rctx->hasSessionId = 1;

        freeMessage(&response);
    }

    {
        RTSP_MESSAGE response;
        int error = -1;

        if (!setupStream(ctx, &response,
						 ctx->AppVersionQuad[0] >= 5 ? "streamid=video/0/0" : "streamid=video",
                         &error)) {
            Limelog("RTSP SETUP streamid=video request failed: %d\n", error);
            ret = error;
            goto Exit;
        }

        if (response.message.response.statusCode != 200) {
            Limelog("RTSP SETUP streamid=video request failed: %d\n",
                response.message.response.statusCode);
            ret = response.message.response.statusCode;
            goto Exit;
        }

        freeMessage(&response);
    }

    if (ctx->AppVersionQuad[0] >= 5) {
        RTSP_MESSAGE response;
        int error = -1;

        if (!setupStream(ctx, &response, "streamid=control/1/0", &error)) {
            Limelog("RTSP SETUP streamid=control request failed: %d\n", error);
            ret = error;
            goto Exit;
        }

        if (response.message.response.statusCode != 200) {
            Limelog("RTSP SETUP streamid=control request failed: %d\n",
                response.message.response.statusCode);
            ret = response.message.response.statusCode;
            goto Exit;
        }

        freeMessage(&response);
    }

    {
        RTSP_MESSAGE response;
        int error = -1;

        if (!sendVideoAnnounce(ctx, &response, &error)) {
            Limelog("RTSP ANNOUNCE request failed: %d\n", error);
            ret = error;
            goto Exit;
        }

        if (response.message.response.statusCode != 200) {
            Limelog("RTSP ANNOUNCE request failed: %d\n",
                response.message.response.statusCode);
            ret = response.message.response.statusCode;
            goto Exit;
        }

        freeMessage(&response);
    }

    {
        RTSP_MESSAGE response;
        int error = -1;

        if (!playStream(ctx, &response, "streamid=video", &error)) {
            Limelog("RTSP PLAY streamid=video request failed: %d\n", error);
            ret = error;
            goto Exit;
        }

        if (response.message.response.statusCode != 200) {
            Limelog("RTSP PLAY streamid=video failed: %d\n",
                response.message.response.statusCode);
            ret = response.message.response.statusCode;
            goto Exit;
        }

        freeMessage(&response);
    }

    {
        RTSP_MESSAGE response;
        int error = -1;

        if (!playStream(ctx, &response, "streamid=audio", &error)) {
            Limelog("RTSP PLAY streamid=audio request failed: %d\n", error);
            ret = error;
            goto Exit;
        }

        if (response.message.response.statusCode != 200) {
            Limelog("RTSP PLAY streamid=audio failed: %d\n",
                response.message.response.statusCode);
            ret = response.message.response.statusCode;
            goto Exit;
        }

        freeMessage(&response);
    }

    ret = 0;

Exit:
    // Cleanup the ENet stuff
    if (rctx->useEnet) {
        if (rctx->peer != NULL) {
            enet_peer_disconnect_now(rctx->peer, 0);
			rctx->peer = NULL;
        }

        if (rctx->client != NULL) {
            enet_host_destroy(rctx->client);
			rctx->client = NULL;
        }
    }

    return ret;
}
