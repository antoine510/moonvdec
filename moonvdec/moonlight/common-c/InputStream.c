#include "Limelight-internal.h"
#include "PlatformSockets.h"
#include "PlatformThreads.h"
#include "LinkedBlockingQueue.h"
#include "Input.h"

#include <openssl/evp.h>

typedef struct _INPUT_STREAM_CTX {
	SOCKET inputSock;
	unsigned char currentAesIv[16];
	int initialized;
	EVP_CIPHER_CTX* cipherContext;
	int cipherInitialized;

	LINKED_BLOCKING_QUEUE packetQueue;
	PLT_THREAD inputSendThread;
} INPUT_STREAM_CTX, *PINPUT_STREAM_CTX;

/*static SOCKET inputSock = INVALID_SOCKET;
static unsigned char currentAesIv[16];
static int initialized;
static EVP_CIPHER_CTX* cipherContext;
static int cipherInitialized;

static LINKED_BLOCKING_QUEUE packetQueue;
static PLT_THREAD inputSendThread;*/

#define MAX_INPUT_PACKET_SIZE 128
#define INPUT_STREAM_TIMEOUT_SEC 10

#define ROUND_TO_PKCS7_PADDED_LEN(x) ((((x) + 15) / 16) * 16)

// Contains input stream packets
typedef struct _PACKET_HOLDER {
    int packetLength;
    union {
        NV_KEYBOARD_PACKET keyboard;
        NV_MOUSE_MOVE_PACKET mouseMove;
        NV_MOUSE_BUTTON_PACKET mouseButton;
        NV_CONTROLLER_PACKET controller;
        NV_MULTI_CONTROLLER_PACKET multiController;
        NV_SCROLL_PACKET scroll;
    } packet;
    LINKED_BLOCKING_QUEUE_ENTRY entry;
} PACKET_HOLDER, *PPACKET_HOLDER;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_CIPHER_CTX_reset(x) EVP_CIPHER_CTX_cleanup(x); EVP_CIPHER_CTX_init(x)
#endif

// Initializes the input stream
int initializeInputStream(PLIMELIGHT_CTX ctx) {
	ctx->istream = (PINPUT_STREAM_CTX)calloc(1, sizeof(INPUT_STREAM_CTX));
	PINPUT_STREAM_CTX ictx = ctx->istream;

	ictx->inputSock = INVALID_SOCKET;
    memcpy(ictx->currentAesIv, ctx->StreamConfig.remoteInputAesIv, sizeof(ictx->currentAesIv));

    // Initialized on first packet
	ictx->cipherInitialized = 0;

    LbqInitializeLinkedBlockingQueue(&ictx->packetQueue, 30);

	ictx->initialized = 1;
    return 0;
}

// Destroys and cleans up the input stream
void destroyInputStream(PINPUT_STREAM_CTX ictx) {
    PLINKED_BLOCKING_QUEUE_ENTRY entry, nextEntry;

    if (ictx->cipherInitialized) {
        EVP_CIPHER_CTX_free(ictx->cipherContext);
		ictx->cipherInitialized = 0;
    }

    entry = LbqDestroyLinkedBlockingQueue(&ictx->packetQueue);

    while (entry != NULL) {
        nextEntry = entry->flink;

        // The entry is stored in the data buffer
        free(entry->data);

        entry = nextEntry;
    }

	ictx->initialized = 0;
	free(ictx);
}

// Checks if values are compatible with controller batching
static int checkDirs(short currentVal, short newVal, int* dir) {
    if (currentVal == newVal) {
        return 1;
    }

    // We want to send a new packet if we've now zeroed an axis
    if (newVal == 0) {
        return 0;
    }

    if (*dir == 0) {
        if (newVal < currentVal) {
            *dir = -1;
        }
        else {
            *dir = 1;
        }
    }
    else if (*dir == -1) {
        return newVal < currentVal;
    }
    else if (newVal < currentVal) {
        return 0;
    }

    return 1;
}

static int addPkcs7PaddingInPlace(unsigned char* plaintext, int plaintextLen) {
    int i;
    int paddedLength = ROUND_TO_PKCS7_PADDED_LEN(plaintextLen);
    unsigned char paddingByte = (unsigned char)(16 - (plaintextLen % 16));

    for (i = plaintextLen; i < paddedLength; i++) {
        plaintext[i] = paddingByte;
    }

    return paddedLength;
}

static int encryptData(PLIMELIGHT_CTX ctx, const unsigned char* plaintext, int plaintextLen,
                       unsigned char* ciphertext, int* ciphertextLen) {
	PINPUT_STREAM_CTX ictx = ctx->istream;

    int ret;
    int len;

    if (ctx->AppVersionQuad[0] >= 7) {
        if (!ictx->cipherInitialized) {
            if ((ictx->cipherContext = EVP_CIPHER_CTX_new()) == NULL) {
                return -1;
            }
			ictx->cipherInitialized = 1;
        }

        // Gen 7 servers use 128-bit AES GCM
        if (EVP_EncryptInit_ex(ictx->cipherContext, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
            ret = -1;
            goto gcm_cleanup;
        }

        // Gen 7 servers uses 16 byte IVs
        if (EVP_CIPHER_CTX_ctrl(ictx->cipherContext, EVP_CTRL_GCM_SET_IVLEN, 16, NULL) != 1) {
            ret = -1;
            goto gcm_cleanup;
        }

        // Initialize again but now provide our key and current IV
        if (EVP_EncryptInit_ex(ictx->cipherContext, NULL, NULL,
                               (const unsigned char*)ctx->StreamConfig.remoteInputAesKey, ictx->currentAesIv) != 1) {
            ret = -1;
            goto gcm_cleanup;
        }

        // Encrypt into the caller's buffer, leaving room for the auth tag to be prepended
        if (EVP_EncryptUpdate(ictx->cipherContext, &ciphertext[16], ciphertextLen, plaintext, plaintextLen) != 1) {
            ret = -1;
            goto gcm_cleanup;
        }

        // GCM encryption won't ever fill ciphertext here but we have to call it anyway
        if (EVP_EncryptFinal_ex(ictx->cipherContext, ciphertext, &len) != 1) {
            ret = -1;
            goto gcm_cleanup;
        }
        LC_ASSERT(len == 0);

        // Read the tag into the caller's buffer
        if (EVP_CIPHER_CTX_ctrl(ictx->cipherContext, EVP_CTRL_GCM_GET_TAG, 16, ciphertext) != 1) {
            ret = -1;
            goto gcm_cleanup;
        }

        // Increment the ciphertextLen to account for the tag
        *ciphertextLen += 16;

        ret = 0;

    gcm_cleanup:
        EVP_CIPHER_CTX_reset(ictx->cipherContext);
    }
    else {
        unsigned char paddedData[MAX_INPUT_PACKET_SIZE];
        int paddedLength;

        if (!ictx->cipherInitialized) {
            if ((ictx->cipherContext = EVP_CIPHER_CTX_new()) == NULL) {
                ret = -1;
                goto cbc_cleanup;
            }
			ictx->cipherInitialized = 1;

            // Prior to Gen 7, 128-bit AES CBC is used for encryption
            if (EVP_EncryptInit_ex(ictx->cipherContext, EVP_aes_128_cbc(), NULL,
                                   (const unsigned char*)ctx->StreamConfig.remoteInputAesKey, ictx->currentAesIv) != 1) {
                ret = -1;
                goto cbc_cleanup;
            }
        }

        // Pad the data to the required block length
        memcpy(paddedData, plaintext, plaintextLen);
        paddedLength = addPkcs7PaddingInPlace(paddedData, plaintextLen);

        if (EVP_EncryptUpdate(ictx->cipherContext, ciphertext, ciphertextLen, paddedData, paddedLength) != 1) {
            ret = -1;
            goto cbc_cleanup;
        }

        ret = 0;

    cbc_cleanup:
        // Nothing to do
        ;
    }

    return ret;
}

// Input thread proc
static void inputSendThreadProc(void* context) {
	PLIMELIGHT_CTX ctx = (PLIMELIGHT_CTX)context;

    SOCK_RET err;
    PPACKET_HOLDER holder;
    char encryptedBuffer[MAX_INPUT_PACKET_SIZE];
    int encryptedSize;

    while (!PltIsThreadInterrupted(&ctx->istream->inputSendThread)) {
        int encryptedLengthPrefix;

        err = LbqWaitForQueueElement(&ctx->istream->packetQueue, (void**)&holder);
        if (err != LBQ_SUCCESS) {
            return;
        }

        // If it's a multi-controller packet we can do batching
        if (holder->packet.multiController.header.packetType == htonl(PACKET_TYPE_MULTI_CONTROLLER)) {
            PPACKET_HOLDER controllerBatchHolder;
            PNV_MULTI_CONTROLLER_PACKET origPkt;
            int dirs[6];

            memset(dirs, 0, sizeof(dirs));

            origPkt = &holder->packet.multiController;
            for (;;) {
                PNV_MULTI_CONTROLLER_PACKET newPkt;

                // Peek at the next packet
                if (LbqPeekQueueElement(&ctx->istream->packetQueue, (void**)&controllerBatchHolder) != LBQ_SUCCESS) {
                    break;
                }

                // If it's not a controller packet, we're done
                if (controllerBatchHolder->packet.multiController.header.packetType != htonl(PACKET_TYPE_MULTI_CONTROLLER)) {
                    break;
                }

                // Check if it's able to be batched
                newPkt = &controllerBatchHolder->packet.multiController;
                if (newPkt->buttonFlags != origPkt->buttonFlags ||
                    newPkt->controllerNumber != origPkt->controllerNumber ||
                    newPkt->activeGamepadMask != origPkt->activeGamepadMask ||
                    !checkDirs(origPkt->leftTrigger, newPkt->leftTrigger, &dirs[0]) ||
                    !checkDirs(origPkt->rightTrigger, newPkt->rightTrigger, &dirs[1]) ||
                    !checkDirs(origPkt->leftStickX, newPkt->leftStickX, &dirs[2]) ||
                    !checkDirs(origPkt->leftStickY, newPkt->leftStickY, &dirs[3]) ||
                    !checkDirs(origPkt->rightStickX, newPkt->rightStickX, &dirs[4]) ||
                    !checkDirs(origPkt->rightStickY, newPkt->rightStickY, &dirs[5])) {
                    // Batching not allowed
                    break;
                }

                // Remove the batchable controller packet
                if (LbqPollQueueElement(&ctx->istream->packetQueue, (void**)&controllerBatchHolder) != LBQ_SUCCESS) {
                    break;
                }

                // Update the original packet
                origPkt->leftTrigger = newPkt->leftTrigger;
                origPkt->rightTrigger = newPkt->rightTrigger;
                origPkt->leftStickX = newPkt->leftStickX;
                origPkt->leftStickY = newPkt->leftStickY;
                origPkt->rightStickX = newPkt->rightStickX;
                origPkt->rightStickY = newPkt->rightStickY;

                // Free the batched packet holder
                free(controllerBatchHolder);
            }
        }
        // If it's a mouse move packet, we can also do batching
        else if (holder->packet.mouseMove.header.packetType == htonl(PACKET_TYPE_MOUSE_MOVE)) {
            PPACKET_HOLDER mouseBatchHolder;
            int totalDeltaX = (short)htons(holder->packet.mouseMove.deltaX);
            int totalDeltaY = (short)htons(holder->packet.mouseMove.deltaY);

            for (;;) {
                int partialDeltaX;
                int partialDeltaY;

                // Peek at the next packet
                if (LbqPeekQueueElement(&ctx->istream->packetQueue, (void**)&mouseBatchHolder) != LBQ_SUCCESS) {
                    break;
                }

                // If it's not a mouse move packet, we're done
                if (mouseBatchHolder->packet.mouseMove.header.packetType != htonl(PACKET_TYPE_MOUSE_MOVE)) {
                    break;
                }

                partialDeltaX = (short)htons(mouseBatchHolder->packet.mouseMove.deltaX);
                partialDeltaY = (short)htons(mouseBatchHolder->packet.mouseMove.deltaY);

                // Check for overflow
                if (partialDeltaX + totalDeltaX > INT16_MAX ||
                    partialDeltaX + totalDeltaX < INT16_MIN ||
                    partialDeltaY + totalDeltaY > INT16_MAX ||
                    partialDeltaY + totalDeltaY < INT16_MIN) {
                    // Total delta would overflow our 16-bit short
                    break;
                }

                // Remove the batchable mouse move packet
                if (LbqPollQueueElement(&ctx->istream->packetQueue, (void**)&mouseBatchHolder) != LBQ_SUCCESS) {
                    break;
                }

                totalDeltaX += partialDeltaX;
                totalDeltaY += partialDeltaY;

                // Free the batched packet holder
                free(mouseBatchHolder);
            }

            // Update the original packet
            holder->packet.mouseMove.deltaX = htons((short)totalDeltaX);
            holder->packet.mouseMove.deltaY = htons((short)totalDeltaY);
        }

        // Encrypt the message into the output buffer while leaving room for the length
        encryptedSize = sizeof(encryptedBuffer) - 4;
        err = encryptData(ctx, (const unsigned char*)&holder->packet, holder->packetLength,
            (unsigned char*)&encryptedBuffer[4], &encryptedSize);
        free(holder);
        if (err != 0) {
            Limelog("Input: Encryption failed: %d\n", (int)err);
            ctx->ListenerCallbacks.connectionTerminated(err);
            return;
        }

        // Prepend the length to the message
        encryptedLengthPrefix = htonl((unsigned long)encryptedSize);
        memcpy(&encryptedBuffer[0], &encryptedLengthPrefix, 4);

        if (ctx->AppVersionQuad[0] < 5) {
            // Send the encrypted payload
            err = send(ctx->istream->inputSock, (const char*) encryptedBuffer,
                (int) (encryptedSize + sizeof(encryptedLengthPrefix)), 0);
            if (err <= 0) {
                Limelog("Input: send() failed: %d\n", (int) LastSocketError());
                ctx->ListenerCallbacks.connectionTerminated(LastSocketError());
                return;
            }
        }
        else {
            // For reasons that I can't understand, NVIDIA decides to use the last 16
            // bytes of ciphertext in the most recent game controller packet as the IV for
            // future encryption. I think it may be a buffer overrun on their end but we'll have
            // to mimic it to work correctly.
            if (ctx->AppVersionQuad[0] >= 7 && encryptedSize >= 16 + sizeof(ctx->istream->currentAesIv)) {
                memcpy(ctx->istream->currentAesIv,
                       &encryptedBuffer[4 + encryptedSize - sizeof(ctx->istream->currentAesIv)],
                       sizeof(ctx->istream->currentAesIv));
            }

            err = (SOCK_RET)sendInputPacketOnControlStream(ctx, (unsigned char*) encryptedBuffer,
                (int) (encryptedSize + sizeof(encryptedLengthPrefix)));
            if (err < 0) {
                Limelog("Input: sendInputPacketOnControlStream() failed: %d\n", (int) err);
                ctx->ListenerCallbacks.connectionTerminated(LastSocketError());
                return;
            }
        }
    }
}

// Begin the input stream
int startInputStream(PLIMELIGHT_CTX ctx) {
    int err;

    // After Gen 5, we send input on the control stream
    if (ctx->AppVersionQuad[0] < 5) {
		ctx->istream->inputSock = connectTcpSocket(ctx, &ctx->RemoteAddr, ctx->RemoteAddrLen,
            35043, INPUT_STREAM_TIMEOUT_SEC);
        if (ctx->istream->inputSock == INVALID_SOCKET) {
            return LastSocketFail();
        }

        enableNoDelay(ctx->istream->inputSock);
    }

    err = PltCreateThread(inputSendThreadProc, ctx, &ctx->istream->inputSendThread);
    if (err != 0) {
        if (ctx->istream->inputSock != INVALID_SOCKET) {
            closeSocket(ctx->istream->inputSock);
			ctx->istream->inputSock = INVALID_SOCKET;
        }
        return err;
    }

    return err;
}

// Stops the input stream
int stopInputStream(PINPUT_STREAM_CTX ictx) {
    // Signal the input send thread
    LbqSignalQueueShutdown(&ictx->packetQueue);
    PltInterruptThread(&ictx->inputSendThread);

    if (ictx->inputSock != INVALID_SOCKET) {
        shutdownTcpSocket(ictx->inputSock);
    }

    PltJoinThread(&ictx->inputSendThread);
    PltCloseThread(&ictx->inputSendThread);

    if (ictx->inputSock != INVALID_SOCKET) {
        closeSocket(ictx->inputSock);
		ictx->inputSock = INVALID_SOCKET;
    }

    return 0;
}

// Send a mouse move event to the streaming machine
int LiSendMouseMoveEvent(PLIMELIGHT_CTX ctx, short deltaX, short deltaY) {
    PPACKET_HOLDER holder;
    int err;

    if (!ctx->istream->initialized) {
        return -2;
    }

    holder = malloc(sizeof(*holder));
    if (holder == NULL) {
        return -1;
    }

    holder->packetLength = sizeof(NV_MOUSE_MOVE_PACKET);
    holder->packet.mouseMove.header.packetType = htonl(PACKET_TYPE_MOUSE_MOVE);
    holder->packet.mouseMove.magic = MOUSE_MOVE_MAGIC;
    // On Gen 5 servers, the header code is incremented by one
    if (ctx->AppVersionQuad[0] >= 5) {
        holder->packet.mouseMove.magic++;
    }
    holder->packet.mouseMove.deltaX = htons(deltaX);
    holder->packet.mouseMove.deltaY = htons(deltaY);

    err = LbqOfferQueueItem(&ctx->istream->packetQueue, holder, &holder->entry);
    if (err != LBQ_SUCCESS) {
        free(holder);
    }

    return err;
}

// Send a mouse button event to the streaming machine
int LiSendMouseButtonEvent(PLIMELIGHT_CTX ctx, char action, int button) {
    PPACKET_HOLDER holder;
    int err;

    if (!ctx->istream->initialized) {
        return -2;
    }

    holder = malloc(sizeof(*holder));
    if (holder == NULL) {
        return -1;
    }

    holder->packetLength = sizeof(NV_MOUSE_BUTTON_PACKET);
    holder->packet.mouseButton.header.packetType = htonl(PACKET_TYPE_MOUSE_BUTTON);
    holder->packet.mouseButton.action = action;
    if (ctx->AppVersionQuad[0] >= 5) {
        holder->packet.mouseButton.action++;
    }
    holder->packet.mouseButton.button = htonl(button);

    err = LbqOfferQueueItem(&ctx->istream->packetQueue, holder, &holder->entry);
    if (err != LBQ_SUCCESS) {
        free(holder);
    }

    return err;
}

// Send a key press event to the streaming machine
int LiSendKeyboardEvent(PLIMELIGHT_CTX ctx, short keyCode, char keyAction, char modifiers) {
    PPACKET_HOLDER holder;
    int err;

    if (!ctx->istream->initialized) {
        return -2;
    }

    holder = malloc(sizeof(*holder));
    if (holder == NULL) {
        return -1;
    }

    holder->packetLength = sizeof(NV_KEYBOARD_PACKET);
    holder->packet.keyboard.header.packetType = htonl(PACKET_TYPE_KEYBOARD);
    holder->packet.keyboard.keyAction = keyAction;
    holder->packet.keyboard.zero1 = 0;
    holder->packet.keyboard.keyCode = keyCode;
    holder->packet.keyboard.modifiers = modifiers;
    holder->packet.keyboard.zero2 = 0;

    err = LbqOfferQueueItem(&ctx->istream->packetQueue, holder, &holder->entry);
    if (err != LBQ_SUCCESS) {
        free(holder);
    }

    return err;
}

static int sendControllerEventInternal(PLIMELIGHT_CTX ctx, short controllerNumber, short activeGamepadMask,
    short buttonFlags, unsigned char leftTrigger, unsigned char rightTrigger,
    short leftStickX, short leftStickY, short rightStickX, short rightStickY)
{
    PPACKET_HOLDER holder;
    int err;

    if (!ctx->istream->initialized) {
        return -2;
    }

    holder = malloc(sizeof(*holder));
    if (holder == NULL) {
        return -1;
    }

    if (ctx->AppVersionQuad[0] == 3) {
        // Generation 3 servers don't support multiple controllers so we send
        // the legacy packet
        holder->packetLength = sizeof(NV_CONTROLLER_PACKET);
        holder->packet.controller.header.packetType = htonl(PACKET_TYPE_CONTROLLER);
        holder->packet.controller.headerA = C_HEADER_A;
        holder->packet.controller.headerB = C_HEADER_B;
        holder->packet.controller.buttonFlags = buttonFlags;
        holder->packet.controller.leftTrigger = leftTrigger;
        holder->packet.controller.rightTrigger = rightTrigger;
        holder->packet.controller.leftStickX = leftStickX;
        holder->packet.controller.leftStickY = leftStickY;
        holder->packet.controller.rightStickX = rightStickX;
        holder->packet.controller.rightStickY = rightStickY;
        holder->packet.controller.tailA = C_TAIL_A;
        holder->packet.controller.tailB = C_TAIL_B;
    }
    else {
        // Generation 4+ servers support passing the controller number
        holder->packetLength = sizeof(NV_MULTI_CONTROLLER_PACKET);
        holder->packet.multiController.header.packetType = htonl(PACKET_TYPE_MULTI_CONTROLLER);
        holder->packet.multiController.headerA = MC_HEADER_A;
        // On Gen 5 servers, the header code is decremented by one
        if (ctx->AppVersionQuad[0] >= 5) {
            holder->packet.multiController.headerA--;
        }
        holder->packet.multiController.headerB = MC_HEADER_B;
        holder->packet.multiController.controllerNumber = controllerNumber;
        holder->packet.multiController.activeGamepadMask = activeGamepadMask;
        holder->packet.multiController.midB = MC_MID_B;
        holder->packet.multiController.buttonFlags = buttonFlags;
        holder->packet.multiController.leftTrigger = leftTrigger;
        holder->packet.multiController.rightTrigger = rightTrigger;
        holder->packet.multiController.leftStickX = leftStickX;
        holder->packet.multiController.leftStickY = leftStickY;
        holder->packet.multiController.rightStickX = rightStickX;
        holder->packet.multiController.rightStickY = rightStickY;
        holder->packet.multiController.tailA = MC_TAIL_A;
        holder->packet.multiController.tailB = MC_TAIL_B;
    }

    err = LbqOfferQueueItem(&ctx->istream->packetQueue, holder, &holder->entry);
    if (err != LBQ_SUCCESS) {
        free(holder);
    }

    return err;
}

// Send a controller event to the streaming machine
int LiSendControllerEvent(PLIMELIGHT_CTX ctx, short buttonFlags, unsigned char leftTrigger, unsigned char rightTrigger,
    short leftStickX, short leftStickY, short rightStickX, short rightStickY)
{
    return sendControllerEventInternal(ctx, 0, 0x1, buttonFlags, leftTrigger, rightTrigger,
        leftStickX, leftStickY, rightStickX, rightStickY);
}

// Send a controller event to the streaming machine
int LiSendMultiControllerEvent(PLIMELIGHT_CTX ctx, short controllerNumber, short activeGamepadMask,
    short buttonFlags, unsigned char leftTrigger, unsigned char rightTrigger,
    short leftStickX, short leftStickY, short rightStickX, short rightStickY)
{
    return sendControllerEventInternal(ctx, controllerNumber, activeGamepadMask,
        buttonFlags, leftTrigger, rightTrigger,
        leftStickX, leftStickY, rightStickX, rightStickY);
}

// Send a scroll event to the streaming machine
int LiSendScrollEvent(PLIMELIGHT_CTX ctx, signed char scrollClicks) {
    PPACKET_HOLDER holder;
    int err;

    if (!ctx->istream->initialized) {
        return -2;
    }

    holder = malloc(sizeof(*holder));
    if (holder == NULL) {
        return -1;
    }

    holder->packetLength = sizeof(NV_SCROLL_PACKET);
    holder->packet.scroll.header.packetType = htonl(PACKET_TYPE_SCROLL);
    holder->packet.scroll.magicA = MAGIC_A;
    // On Gen 5 servers, the header code is incremented by one
    if (ctx->AppVersionQuad[0] >= 5) {
        holder->packet.scroll.magicA++;
    }
    holder->packet.scroll.zero1 = 0;
    holder->packet.scroll.zero2 = 0;
    holder->packet.scroll.scrollAmt1 = htons(scrollClicks * 120);
    holder->packet.scroll.scrollAmt2 = holder->packet.scroll.scrollAmt1;
    holder->packet.scroll.zero3 = 0;

    err = LbqOfferQueueItem(&ctx->istream->packetQueue, holder, &holder->entry);
    if (err != LBQ_SUCCESS) {
        free(holder);
    }

    return err;
}
