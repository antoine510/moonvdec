#include "Platform.h"
#include "Limelight-internal.h"
#include "LinkedBlockingQueue.h"
#include "Video.h"

typedef struct _VIDEO_DEPACKETIZER_CTX {
	PLENTRY nalChainHead;
	int nalChainDataLength;

	unsigned int nextFrameNumber;
	unsigned int startFrameNumber;
	int waitingForNextSuccessfulFrame;
	int waitingForIdrFrame;
	unsigned int lastPacketInStream;
	int decodingFrame;
	int strictIdrFrameWait;
	unsigned long long firstPacketReceiveTime;
	int dropStatePending;

	unsigned int consecutiveFrameDrops;

	LINKED_BLOCKING_QUEUE decodeUnitQueue;
} VIDEO_DEPACKETIZER_CTX, *PVIDEO_DEPACKETIZER_CTX;

/*static PLENTRY nalChainHead;
static int nalChainDataLength;

static unsigned int nextFrameNumber;
static unsigned int startFrameNumber;
static int waitingForNextSuccessfulFrame;
static int waitingForIdrFrame;
static unsigned int lastPacketInStream;
static int decodingFrame;
static int strictIdrFrameWait;
static unsigned long long firstPacketReceiveTime;
static int dropStatePending;*/

#define CONSECUTIVE_DROP_LIMIT 120
/*static unsigned int consecutiveFrameDrops;

static LINKED_BLOCKING_QUEUE decodeUnitQueue;*/

typedef struct _BUFFER_DESC {
    char* data;
    unsigned int offset;
    unsigned int length;
} BUFFER_DESC, *PBUFFER_DESC;

// Init
void initializeVideoDepacketizer(PLIMELIGHT_CTX ctx, int pktSize) {
	ctx->vdepack = (PVIDEO_DEPACKETIZER_CTX)calloc(1, sizeof(VIDEO_DEPACKETIZER_CTX));
	PVIDEO_DEPACKETIZER_CTX vdctx = ctx->vdepack;

    if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        LbqInitializeLinkedBlockingQueue(&vdctx->decodeUnitQueue, 15);
    }

	vdctx->nextFrameNumber = 1;
	vdctx->startFrameNumber = 0;
	vdctx->waitingForNextSuccessfulFrame = 0;
	vdctx->waitingForIdrFrame = 1;
	vdctx->lastPacketInStream = UINT32_MAX;
	vdctx->decodingFrame = 0;
	vdctx->firstPacketReceiveTime = 0;
	vdctx->dropStatePending = 0;
	vdctx->strictIdrFrameWait = !isReferenceFrameInvalidationEnabled(ctx);
}

// Free the NAL chain
static void cleanupFrameState(PVIDEO_DEPACKETIZER_CTX vdctx) {
    PLENTRY lastEntry;

    while (vdctx->nalChainHead != NULL) {
        lastEntry = vdctx->nalChainHead;
		vdctx->nalChainHead = lastEntry->next;
        free(lastEntry);
    }

	vdctx->nalChainDataLength = 0;
}

// Cleanup frame state and set that we're waiting for an IDR Frame
static void dropFrameState(PLIMELIGHT_CTX ctx) {
	PVIDEO_DEPACKETIZER_CTX vdctx = ctx->vdepack;

    // This may only be called at frame boundaries
    LC_ASSERT(!decodingFrame);

    // We're dropping frame state now
	vdctx->dropStatePending = 0;

    // We'll need an IDR frame now if we're in strict mode
    if (vdctx->strictIdrFrameWait) {
		vdctx->waitingForIdrFrame = 1;
    }

    // Count the number of consecutive frames dropped
	vdctx->consecutiveFrameDrops++;

    // If we reach our limit, immediately request an IDR frame and reset
    if (vdctx->consecutiveFrameDrops == CONSECUTIVE_DROP_LIMIT) {
        Limelog("Reached consecutive drop limit\n");

        // Restart the count
		vdctx->consecutiveFrameDrops = 0;

        // Request an IDR frame
		vdctx->waitingForIdrFrame = 1;
        requestIdrOnDemand(ctx->cstream);
    }

    cleanupFrameState(ctx->vdepack);
}

// Cleanup the list of decode units
static void freeDecodeUnitList(PLINKED_BLOCKING_QUEUE_ENTRY entry) {
    PLINKED_BLOCKING_QUEUE_ENTRY nextEntry;

    while (entry != NULL) {
        nextEntry = entry->flink;

        freeQueuedDecodeUnit((PQUEUED_DECODE_UNIT)entry->data);

        entry = nextEntry;
    }
}

void stopVideoDepacketizer(PLIMELIGHT_CTX ctx) {
    if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        LbqSignalQueueShutdown(&ctx->vdepack->decodeUnitQueue);
    }
}

// Cleanup video depacketizer and free malloced memory
void destroyVideoDepacketizer(PLIMELIGHT_CTX ctx) {
    if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        freeDecodeUnitList(LbqDestroyLinkedBlockingQueue(&ctx->vdepack->decodeUnitQueue));
    }

    cleanupFrameState(ctx->vdepack);
	free(ctx->vdepack);
}

// Returns 1 if candidate is a frame start and 0 otherwise
static int isSeqFrameStart(PBUFFER_DESC candidate) {
    return (candidate->length == 4 && candidate->data[candidate->offset + candidate->length - 1] == 1);
}

// Returns 1 if candidate is an Annex B start and 0 otherwise
static int isSeqAnnexBStart(PBUFFER_DESC candidate) {
    return (candidate->data[candidate->offset + candidate->length - 1] == 1);
}

// Returns 1 if candidate is padding and 0 otherwise
static int isSeqPadding(PBUFFER_DESC candidate) {
    return (candidate->data[candidate->offset + candidate->length - 1] == 0);
}

// Returns 1 on success, 0 otherwise
static int getSpecialSeq(PBUFFER_DESC current, PBUFFER_DESC candidate) {
    if (current->length < 3) {
        return 0;
    }

    if (current->data[current->offset] == 0 &&
        current->data[current->offset + 1] == 0) {
        // Padding or frame start
        if (current->data[current->offset + 2] == 0) {
            if (current->length >= 4 && current->data[current->offset + 3] == 1) {
                // Frame start
                candidate->data = current->data;
                candidate->offset = current->offset;
                candidate->length = 4;
                return 1;
            }
            else {
                // Padding
                candidate->data = current->data;
                candidate->offset = current->offset;
                candidate->length = 3;
                return 1;
            }
        }
        else if (current->data[current->offset + 2] == 1) {
            // NAL start
            candidate->data = current->data;
            candidate->offset = current->offset;
            candidate->length = 3;
            return 1;
        }
    }

    return 0;
}

// Get the first decode unit available
int getNextQueuedDecodeUnit(PVIDEO_DEPACKETIZER_CTX vdctx, PQUEUED_DECODE_UNIT* qdu) {
    int err = LbqWaitForQueueElement(&vdctx->decodeUnitQueue, (void**)qdu);
    if (err == LBQ_SUCCESS) {
        return 1;
    }
    else {
        return 0;
    }
}

// Cleanup a decode unit by freeing the buffer chain and the holder
void freeQueuedDecodeUnit(PQUEUED_DECODE_UNIT qdu) {
    PLENTRY lastEntry;

    while (qdu->decodeUnit.bufferList != NULL) {
        lastEntry = qdu->decodeUnit.bufferList;
        qdu->decodeUnit.bufferList = lastEntry->next;
        free(lastEntry);
    }

    free(qdu);
}


// Returns 1 if the special sequence describes an I-frame
static int isSeqReferenceFrameStart(PBUFFER_DESC specialSeq) {
    switch (specialSeq->data[specialSeq->offset + specialSeq->length]) {
        case 0x20:
        case 0x22:
        case 0x24:
        case 0x26:
        case 0x28:
        case 0x2A:
            // H265
            return 1;

        case 0x65:
            // H264
            return 1;

        default:
            return 0;
    }
}

// Returns 1 if this buffer describes an IDR frame
static int isIdrFrameStart(PBUFFER_DESC buffer) {
    BUFFER_DESC specialSeq;
    return getSpecialSeq(buffer, &specialSeq) &&
        isSeqFrameStart(&specialSeq) &&
        (specialSeq.data[specialSeq.offset + specialSeq.length] == 0x67 || // H264 SPS
         specialSeq.data[specialSeq.offset + specialSeq.length] == 0x40); // H265 VPS
}

// Reassemble the frame with the given frame number
static void reassembleFrame(PLIMELIGHT_CTX ctx, int frameNumber) {
	PVIDEO_DEPACKETIZER_CTX vdctx = ctx->vdepack;

    if (vdctx->nalChainHead != NULL) {
        PQUEUED_DECODE_UNIT qdu = (PQUEUED_DECODE_UNIT)malloc(sizeof(*qdu));
        if (qdu != NULL) {
            qdu->decodeUnit.bufferList = vdctx->nalChainHead;
            qdu->decodeUnit.fullLength = vdctx->nalChainDataLength;
            qdu->decodeUnit.frameNumber = frameNumber;
            qdu->decodeUnit.receiveTimeMs = vdctx->firstPacketReceiveTime;

            // IDR frames will have leading CSD buffers
            if (vdctx->nalChainHead->bufferType != BUFFER_TYPE_PICDATA) {
                qdu->decodeUnit.frameType = FRAME_TYPE_IDR;
            }
            else {
                qdu->decodeUnit.frameType = FRAME_TYPE_PFRAME;
            }

			vdctx->nalChainHead = NULL;
			vdctx->nalChainDataLength = 0;

            if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
                if (LbqOfferQueueItem(&vdctx->decodeUnitQueue, qdu, &qdu->entry) == LBQ_BOUND_EXCEEDED) {
                    Limelog("Video decode unit queue overflow\n");

                    // Clear frame state and wait for an IDR
					vdctx->nalChainHead = qdu->decodeUnit.bufferList;
					vdctx->nalChainDataLength = qdu->decodeUnit.fullLength;
                    dropFrameState(ctx);

                    // Free the DU
                    free(qdu);

                    // Flush the decode unit queue
                    freeDecodeUnitList(LbqFlushQueueItems(&vdctx->decodeUnitQueue));

                    // FIXME: Get proper bounds to use reference frame invalidation
                    requestIdrOnDemand(ctx->cstream);
                    return;
                }
            }
            else {
                int ret = ctx->VideoCallbacks.submitDecodeUnit(&qdu->decodeUnit, ctx->DecodeUnitContext);

                freeQueuedDecodeUnit(qdu);

                if (ret == DR_NEED_IDR) {
                    Limelog("Requesting IDR frame on behalf of DR\n");
                    requestDecoderRefresh(ctx);
                }
            }

            // Notify the control connection
            connectionReceivedCompleteFrame(ctx->cstream, frameNumber);

            // Clear frame drops
			vdctx->consecutiveFrameDrops = 0;
        }
    }
}


#define AVC_NAL_TYPE_SPS 0x67
#define AVC_NAL_TYPE_PPS 0x68
#define HEVC_NAL_TYPE_VPS 0x40
#define HEVC_NAL_TYPE_SPS 0x42
#define HEVC_NAL_TYPE_PPS 0x44

static int getBufferFlags(char* data, int length) {
    BUFFER_DESC buffer;
    BUFFER_DESC candidate;

    buffer.data = data;
    buffer.length = (unsigned int)length;
    buffer.offset = 0;

    if (!getSpecialSeq(&buffer, &candidate) || !isSeqFrameStart(&candidate)) {
        return BUFFER_TYPE_PICDATA;
    }

    switch (candidate.data[candidate.offset + candidate.length]) {
        case AVC_NAL_TYPE_SPS:
        case HEVC_NAL_TYPE_SPS:
            return BUFFER_TYPE_SPS;

        case AVC_NAL_TYPE_PPS:
        case HEVC_NAL_TYPE_PPS:
            return BUFFER_TYPE_PPS;

        case HEVC_NAL_TYPE_VPS:
            return BUFFER_TYPE_VPS;

        default:
            return BUFFER_TYPE_PICDATA;
    }
}

static void queueFragment(PVIDEO_DEPACKETIZER_CTX vdctx, char* data, int offset, int length) {
    PLENTRY entry = (PLENTRY)malloc(sizeof(*entry) + length);
    if (entry != NULL) {
        entry->next = NULL;
        entry->length = length;
        entry->data = (char*)(entry + 1);

        memcpy(entry->data, &data[offset], entry->length);

        entry->bufferType = getBufferFlags(entry->data, entry->length);

		vdctx->nalChainDataLength += entry->length;

        if (vdctx->nalChainHead == NULL) {
			vdctx->nalChainHead = entry;
        }
        else {
            PLENTRY currentEntry = vdctx->nalChainHead;

            while (currentEntry->next != NULL) {
                currentEntry = currentEntry->next;
            }

            currentEntry->next = entry;
        }
    }
}

// Process an RTP Payload
static void processRtpPayloadSlow(PVIDEO_DEPACKETIZER_CTX vdctx, PNV_VIDEO_PACKET videoPacket, PBUFFER_DESC currentPos) {
    BUFFER_DESC specialSeq;
    int decodingVideo = 0;

    // We should not have any NALUs when processing the first packet in an IDR frame
    LC_ASSERT(nalChainHead == NULL);

    while (currentPos->length != 0) {
        int start = currentPos->offset;

        if (getSpecialSeq(currentPos, &specialSeq)) {
            if (isSeqAnnexBStart(&specialSeq)) {
                // Now we're decoding video
                decodingVideo = 1;

                if (isSeqFrameStart(&specialSeq)) {
                    // Now we're working on a frame
					vdctx->decodingFrame = 1;

                    if (isSeqReferenceFrameStart(&specialSeq)) {
                        // No longer waiting for an IDR frame
						vdctx->waitingForIdrFrame = 0;

                        // Cancel any pending IDR frame request
						vdctx->waitingForNextSuccessfulFrame = 0;
                    }
                }

                // Skip the start sequence
                currentPos->length -= specialSeq.length;
                currentPos->offset += specialSeq.length;
            }
            else {
                // Not decoding video
                decodingVideo = 0;

                // Just skip this byte
                currentPos->length--;
                currentPos->offset++;
            }
        }

        // Move to the next special sequence
        while (currentPos->length != 0) {
            // Check if this should end the current NAL
            if (getSpecialSeq(currentPos, &specialSeq)) {
                if (decodingVideo || !isSeqPadding(&specialSeq)) {
                    break;
                }
            }

            // This byte is part of the NAL data
            currentPos->offset++;
            currentPos->length--;
        }

        if (decodingVideo) {
            queueFragment(vdctx, currentPos->data, start, currentPos->offset - start);
        }
    }
}

// Dumps the decode unit queue and ensures the next frame submitted to the decoder will be
// an IDR frame
void requestDecoderRefresh(PLIMELIGHT_CTX ctx) {
    // Wait for the next IDR frame
    ctx->vdepack->waitingForIdrFrame = 1;

    // Flush the decode unit queue
    if ((ctx->VideoCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        freeDecodeUnitList(LbqFlushQueueItems(&ctx->vdepack->decodeUnitQueue));
    }

    // Request the receive thread drop its state
    // on the next call. We can't do it here because
    // it may be trying to queue DUs and we'll nuke
    // the state out from under it.
	ctx->vdepack->dropStatePending = 1;

    // Request the IDR frame
    requestIdrOnDemand(ctx->cstream);
}

// Return 1 if packet is the first one in the frame
static int isFirstPacket(char flags) {
    // Clear the picture data flag
    flags &= ~FLAG_CONTAINS_PIC_DATA;

    // Check if it's just the start or both start and end of a frame
    return (flags == (FLAG_SOF | FLAG_EOF) ||
        flags == FLAG_SOF);
}

// Adds a fragment directly to the queue
static void processRtpPayloadFast(PVIDEO_DEPACKETIZER_CTX vdctx, BUFFER_DESC location) {
    queueFragment(vdctx, location.data, location.offset, location.length);
}

// Process an RTP Payload
void processRtpPayload(PLIMELIGHT_CTX ctx, PNV_VIDEO_PACKET videoPacket, int length, unsigned long long receiveTimeMs) {
	PVIDEO_DEPACKETIZER_CTX vdctx = ctx->vdepack;

	BUFFER_DESC currentPos;
    int frameIndex;
    char flags;
    unsigned int firstPacket;
    unsigned int streamPacketIndex;

    // Mask the top 8 bits from the SPI
    videoPacket->streamPacketIndex >>= 8;
    videoPacket->streamPacketIndex &= 0xFFFFFF;

    currentPos.data = (char*)(videoPacket + 1);
    currentPos.offset = 0;
    currentPos.length = length - sizeof(*videoPacket);

    frameIndex = videoPacket->frameIndex;
    flags = videoPacket->flags;
    firstPacket = isFirstPacket(flags);

    LC_ASSERT((flags & ~(FLAG_SOF | FLAG_EOF | FLAG_CONTAINS_PIC_DATA)) == 0);

    streamPacketIndex = videoPacket->streamPacketIndex;

    // Drop packets from a previously corrupt frame
    if (isBefore32(frameIndex, vdctx->nextFrameNumber)) {
        return;
    }

    // The FEC queue can sometimes recover corrupt frames (see comments in RtpFecQueue).
    // It almost always detects them before they get to us, but in case it doesn't
    // the streamPacketIndex not matching correctly should find nearly all of the rest.
    if (isBefore24(streamPacketIndex, U24(vdctx->lastPacketInStream + 1)) ||
            (!firstPacket && streamPacketIndex != U24(vdctx->lastPacketInStream + 1))) {
        Limelog("Depacketizer detected corrupt frame: %d", frameIndex);
		vdctx->decodingFrame = 0;
		vdctx->nextFrameNumber = frameIndex + 1;
		vdctx->waitingForNextSuccessfulFrame = 1;
        dropFrameState(ctx);
        return;
    }

    // Notify the listener of the latest frame we've seen from the PC
    connectionSawFrame(ctx->cstream, frameIndex);

    // Verify that we didn't receive an incomplete frame
    LC_ASSERT(firstPacket ^ decodingFrame);

    // Check sequencing of this frame to ensure we didn't
    // miss one in between
    if (firstPacket) {
        // Make sure this is the next consecutive frame
        if (isBefore32(vdctx->nextFrameNumber, frameIndex)) {
            Limelog("Network dropped an entire frame\n");
			vdctx->nextFrameNumber = frameIndex;

            // Wait until next complete frame
			vdctx->waitingForNextSuccessfulFrame = 1;
            dropFrameState(ctx);
        }
        else {
            LC_ASSERT(nextFrameNumber == frameIndex);
        }

        // We're now decoding a frame
		vdctx->decodingFrame = 1;
		vdctx->firstPacketReceiveTime = receiveTimeMs;
    }

	vdctx->lastPacketInStream = streamPacketIndex;

    // If this is the first packet, skip the frame header (if one exists)
    if (firstPacket){
        if ((ctx->AppVersionQuad[0] > 7) ||
            (ctx->AppVersionQuad[0] == 7 && ctx->AppVersionQuad[1] > 1) ||
            (ctx->AppVersionQuad[0] == 7 && ctx->AppVersionQuad[1] == 1 && ctx->AppVersionQuad[2] >= 350)) {
            // >= 7.1.350 should use the 8 byte header again
            currentPos.offset += 8;
            currentPos.length -= 8;
        }
        else if ((ctx->AppVersionQuad[0] > 7) ||
            (ctx->AppVersionQuad[0] == 7 && ctx->AppVersionQuad[1] > 1) ||
            (ctx->AppVersionQuad[0] == 7 && ctx->AppVersionQuad[1] == 1 && ctx->AppVersionQuad[2] >= 320)) {
            // [7.1.320, 7.1.350) should use the 12 byte frame header
            currentPos.offset += 12;
            currentPos.length -= 12;
        }
        else if (ctx->AppVersionQuad[0] >= 5) {
            // [5.x, 7.1.320) should use the 8 byte header
            currentPos.offset += 8;
            currentPos.length -= 8;
        }
        else {
            // Other versions don't have a frame header at all
        }
    }

    if (firstPacket && isIdrFrameStart(&currentPos))
    {
        // SPS and PPS prefix is padded between NALs, so we must decode it with the slow path
        processRtpPayloadSlow(vdctx, videoPacket, &currentPos);
    }
    else
    {
        processRtpPayloadFast(vdctx, currentPos);
    }

    if (flags & FLAG_EOF) {
        // Move on to the next frame
		vdctx->decodingFrame = 0;
		vdctx->nextFrameNumber = frameIndex + 1;

        // If waiting for next successful frame and we got here
        // with an end flag, we can send a message to the server
        if (vdctx->waitingForNextSuccessfulFrame) {
            // This is the next successful frame after a loss event
            connectionDetectedFrameLoss(ctx, vdctx->startFrameNumber, frameIndex - 1);
			vdctx->waitingForNextSuccessfulFrame = 0;
        }

        // If we need an IDR frame first, then drop this frame
        if (vdctx->waitingForIdrFrame) {
            Limelog("Waiting for IDR frame\n");

            dropFrameState(ctx);
            return;
        }

        // Carry out any pending state drops. We can't just do this
        // arbitrarily in the middle of processing a frame because
        // may cause the depacketizer state to become corrupted. For
        // example, if we drop state after the first packet, the
        // depacketizer will next try to process a non-SOF packet,
        // and cause it to assert.
        if (vdctx->dropStatePending) {
            dropFrameState(ctx);
            return;
        }

        reassembleFrame(ctx, frameIndex);

		vdctx->startFrameNumber = vdctx->nextFrameNumber;
    }
}

// Add an RTP Packet to the queue
void queueRtpPacket(PLIMELIGHT_CTX ctx, PRTPFEC_QUEUE_ENTRY queueEntry) {
    int dataOffset;

    dataOffset = sizeof(*queueEntry->packet);
    if (queueEntry->packet->header & FLAG_EXTENSION) {
        dataOffset += 4; // 2 additional fields
    }

    processRtpPayload(ctx, (PNV_VIDEO_PACKET)(((char*)queueEntry->packet) + dataOffset),
                      queueEntry->length - dataOffset,
                      queueEntry->receiveTimeMs);
}
