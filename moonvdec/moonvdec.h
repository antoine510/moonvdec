/*****************************************************************//**
 * \file   moonvdec.h
 * \brief  API for the moonvdec library
 * 
 * \author Antoine Richard <antoine.richard@loria.fr>
 * \date   August 2020
 *********************************************************************/

#pragma once

/**
 * This library uses the STDCALL convention for its callbacks.
 */
#define CALLBACK_CONV __stdcall

#ifdef MOONVDEC_EXPORT
#define API_EXPORT __declspec(dllexport)
#else
#define API_EXPORT __declspec(dllimport)
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Structure used to configure a moonlight stream.
	 */
	struct mvd_StreamConfiguration {
		int width;	///< Width of the desired video stream
		int height;	///< Height of the desired video stream

		int fps;	///< FPS of the desired video stream

		int bitrate;	///< Bitrate of the desired video stream (audio adds another ~1 Mbps)

		int packetSize;	///< Max video packet size in bytes (use 1024 if unsure)

		/// Set to non-zero value to enable remote (over the Internet) streaming optimizations. If unsure, set to 0.
		int streamingRemotely;

		/**
		 * Specifies the channel configuration of the audio stream.
		 * - 0 is for Stereo sound
		 * - 1 is for 5.1 surround
		 */
		int audioConfiguration;

		/// Specifies that the client can accept an H.265 video stream if the server is able to provide one.
		int supportsHevc;

		/**
		 * Specifies that the client is requesting an HDR H.265 video stream.
		 * This should only be set if:
		 * - The client decoder supports HEVC Main10 profile (supportsHevc must be set too)
		 * - The server has support for HDR as indicated by ServerCodecModeSupport in /serverinfo
		 * - The app supports HDR as indicated by IsHdrSupported in /applist
		 */
		int enableHdr;

		/**
		 * Specifies the percentage that the specified bitrate will be adjusted.
		 * when an HEVC stream will be delivered. This allows clients to opt to
		 * reduce bandwidth when HEVC is chosen as the video codec rather than
		 * (or in addition to) improving image quality.
		 */
		int hevcBitratePercentageMultiplier;

		/**
		 * If specified, the client's display refresh rate x 100. For example,.
		 * 59.94 Hz would be specified as 5994. This is used by recent versions
		 * of GFE for enhanced frame pacing.
		 */
		int clientRefreshRateX100;

		
		char remoteInputAesKey[16];	///< Internal use only
		char remoteInputAesIv[16];	///< Internal use only
	};


	/**
	* Type used to represent a stream source.
	* It can be obtained from the source address using mvd_GetStreamSource
	* @see mvd_GetStreamSource()
	*/
	typedef void* mvd_StreamSource;

	/**
	* Callback format for logging.
	* @param msg The message to log
	*/
	typedef void(CALLBACK_CONV* mvd_CLogCallback)(const char* msg);

	/**
	* Callback format for receiving frames from a stream
	* @param frameNV12 The stream frame in NV12 format
	* @param context The context object provided when starting the stream
	*/
	typedef void(CALLBACK_CONV* mvd_CFrameCallback)(const uint8_t* frameNV12, void* context);

	/**
	* Initializes the moonvdec library
	* @param cb A callback to receive library logs.
	* @return 0 on success, a negative number on error
	*/
	API_EXPORT int mvd_Init(mvd_CLogCallback cb);

	/**
	 * Closes the moonvdec library
	 */
	API_EXPORT void mvd_Close();

	/**
	 * Creates a mvd_StreamSource object from an address
	 * @param address The source's address as a host name or IP address
	 * @return The created mvd_StreamSource or nullptr if an error occured
	 */
	API_EXPORT mvd_StreamSource mvd_GetStreamSource(const char* address);

	/**
	 * Discards a stream source, releasing ressources
	 * @param src The source to discard
	 */
	API_EXPORT void mvd_DiscardStreamSource(mvd_StreamSource src);

	/**
	 * Pairs this stream source to your software.
	 * This function can be called when already paired. It will simply return immediatly.
	 * @param src The stream source to pair
	 * @param PIN The PIN your user should enter on the GameStream side
	 * @return 0 on success, a negative number on error
	 */
	API_EXPORT int mvd_PairStreamSource(mvd_StreamSource src, const char* PIN);

	/**
	 * Retrieves a list of the available apps to be launched by this stream source.
	 * The ids and names of the apps are retrieved.
	 * You do not have to free any memory following calls to this function.
	 * @param src The stream source to query
	 * @param ids [out] Pointer at which to receive an array of integer ids
	 * @param names [out] Pointer at which to receive an array of names as wide strings (wchar_t*)
	 * @param lengths [out] Pointer at which to receive an array containing the lenghts of the aforementioned names
	 * @return 0 on success, a negative number on error
	 */
	API_EXPORT int mvd_GetAppList(mvd_StreamSource src, const int** ids, const wchar_t* const** names, const int** lengths);

	/**
	 * Launches an app on a stream source.
	 * @param src The stream source which launches the app
	 * @param appID The ID of the app to launch
	 * @param sconfig The configuration of the app and stream
	 */
	API_EXPORT void mvd_LaunchApp(mvd_StreamSource src, int appID, mvd_StreamConfiguration* sconfig);

	/**
	 * Starts a stream.
	 * @param src The stream source from which to begin streaming
	 * @param sconfig The configuration of the app and stream
	 * @param outFramesCB A callback to be called at each frame reception
	 * @param outFramesContext Any context object of your choosing which will be transfered to your callback function
	 * @return 0 on success, a negative number on error
	 */
	API_EXPORT int mvd_StartStream(mvd_StreamSource src, mvd_StreamConfiguration* sconfig,
								   mvd_CFrameCallback outFramesCB, void* outFramesContext);

	/**
	 * Stops a stream.
	 * @param src The stream source to stop
	 */
	API_EXPORT void mvd_StopStream(mvd_StreamSource src);


#ifdef __cplusplus
}
#endif
