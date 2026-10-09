/*
 * Copyright 2026 Kartik Gohil
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * libuspmtp.h
 *
 * Public C API for libuspmtp – a USP (TR-369) client library that
 * communicates with OB-USPA (OpenBroadband USP Agent) over a UNIX domain
 * socket using the OB-USPA UDS MTP frame format.
 *
 * This header is valid C (C89/C99/C11) and valid C++.  It must be included
 * before any implementation headers.
 *
 * Ownership model
 * ---------------
 * Every opaque handle returned by usp_controller_new() is owned by the caller
 * and MUST be released exactly once with usp_controller_free().  Passing a
 * handle to usp_controller_free() a second time is undefined behaviour.
 *
 * Thread safety
 * -------------
 * A single UspControllerHandle MUST NOT be used concurrently from multiple
 * threads without external synchronisation.  Internally the library uses a
 * background worker thread to manage the socket connection; all public API
 * functions are safe to call from any single thread.
 *
 * Error model
 * -----------
 * All functions that can fail return an int status code.  The meanings are:
 *   USP_OK                 – success
 *   USP_ERR_NULL_POINTER   – a required pointer argument was NULL
 *   USP_ERR_INVALID_UTF8   – a string argument contained invalid UTF-8
 *   USP_ERR_BUFFER_TOO_SMALL – the output buffer was too small
 *   USP_ERR_RUNTIME        – failed to initialise the internal runtime
 *   USP_ERR_USP            – a USP-level error occurred (see last_error)
 *   USP_ERR_NOT_FOUND      – the requested parameter was not in the response
 *   USP_ERR_INVALID_ARGUMENT – an argument had an invalid value
 *   USP_ERR_PANIC          – an internal panic / unhandled exception
 *
 * After USP_ERR_USP, call usp_controller_last_error() to retrieve a
 * human-readable description of the error.
 *
 * Response encoding (get_many, set_many, operate, subscribe_*_and_get)
 * ---------------------------------------------------------------------
 * The multi-valued response functions write a TSV-like text format to the
 * caller-supplied output buffer.  Each line ends with '\n'.  Fields within a
 * line are separated by '\t'.  Literal '\', '\t', and '\n' characters in
 * path or value strings are escaped as '\\', '\t', '\n'.
 *
 *   GET response lines:
 *     "PARAM\t<path>\t<value>\n"
 *     "ERROR\t<path>\t<err_code>\t<err_msg>\n"
 *
 *   SET response lines:
 *     "UPDATED\t<path>\n"
 *     "ERROR\t<path>\t<err_code>\t<err_msg>\n"
 *
 *   OPERATE response lines:
 *     "OUTPUT\t<key>\t<value>\n"
 *
 * Subscription notification type constants
 * -----------------------------------------
 *   USP_SUBSCRIPTION_VALUE_CHANGE    – notify when a parameter changes
 *   USP_SUBSCRIPTION_OBJECT_CREATION – notify when an instance is created
 *   USP_SUBSCRIPTION_OBJECT_DELETION – notify when an instance is deleted
 *
 * USP error codes (TR-369 Annex A)
 * ---------------------------------
 * Named constants are provided for all standard USP error codes.  Vendor-
 * defined codes fall in the range [7800, 7999] and can be tested with the
 * usp_error_is_vendor_defined() helper.
 */

#ifndef LIBUSPMTP_H
#define LIBUSPMTP_H

#include <stddef.h>
#include <stdint.h>

/* ── Export/import visibility ─────────────────────────────────────────────── */

#if defined(_WIN32)
#  if defined(LIBUSPMTP_BUILD_SHARED)
#    if defined(LIBUSPMTP_EXPORTS)
#      define LIBUSP_API __declspec(dllexport)
#    else
#      define LIBUSP_API __declspec(dllimport)
#    endif
#  else
#    define LIBUSP_API
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define LIBUSP_API __attribute__((visibility("default")))
#else
#  define LIBUSP_API
#endif

/* ── Named USP error codes (TR-369 Annex A) ──────────────────────────────── */

#define USP_ERROR_CODE_MESSAGE_FAILED             7000u
#define USP_ERROR_CODE_MESSAGE_NOT_SUPPORTED      7001u
#define USP_ERROR_CODE_REQUEST_DENIED             7002u
#define USP_ERROR_CODE_INTERNAL_ERROR             7003u
#define USP_ERROR_CODE_INVALID_ARGUMENTS          7004u
#define USP_ERROR_CODE_RESOURCES_EXCEEDED         7005u
#define USP_ERROR_CODE_PERMISSION_DENIED          7006u
#define USP_ERROR_CODE_INVALID_CONFIGURATION      7007u
#define USP_ERROR_CODE_INVALID_PATH_SYNTAX        7008u
#define USP_ERROR_CODE_PARAMETER_ACTION_FAILED    7009u
#define USP_ERROR_CODE_UNSUPPORTED_PARAMETER      7010u
#define USP_ERROR_CODE_INVALID_TYPE               7011u
#define USP_ERROR_CODE_INVALID_VALUE              7012u
#define USP_ERROR_CODE_NON_WRITABLE_PARAMETER     7013u
#define USP_ERROR_CODE_VALUE_CONFLICT             7014u
#define USP_ERROR_CODE_OPERATION_ERROR            7015u
#define USP_ERROR_CODE_OBJECT_DOES_NOT_EXIST      7016u
#define USP_ERROR_CODE_OBJECT_COULD_NOT_BE_CREATED 7017u
#define USP_ERROR_CODE_OBJECT_IS_NOT_A_TABLE      7018u
#define USP_ERROR_CODE_NON_CREATABLE_OBJECT       7019u
#define USP_ERROR_CODE_OBJECT_COULD_NOT_BE_UPDATED 7020u
#define USP_ERROR_CODE_REQUIRED_PARAMETER_FAILED  7021u
#define USP_ERROR_CODE_COMMAND_FAILURE            7022u
#define USP_ERROR_CODE_COMMAND_CANCELED           7023u
#define USP_ERROR_CODE_DELETE_FAILURE             7024u
#define USP_ERROR_CODE_DUPLICATE_KEY              7025u
#define USP_ERROR_CODE_INVALID_PATH               7026u
#define USP_ERROR_CODE_INVALID_COMMAND_ARGUMENTS  7027u
#define USP_ERROR_CODE_VENDOR_DEFINED_MIN         7800u
#define USP_ERROR_CODE_VENDOR_DEFINED_MAX         7999u

/* Legacy macro aliases matching the Rust-generated header (cbindgen output). */
#define UspErrorCode_MESSAGE_FAILED             USP_ERROR_CODE_MESSAGE_FAILED
#define UspErrorCode_MESSAGE_NOT_SUPPORTED      USP_ERROR_CODE_MESSAGE_NOT_SUPPORTED
#define UspErrorCode_REQUEST_DENIED             USP_ERROR_CODE_REQUEST_DENIED
#define UspErrorCode_INTERNAL_ERROR             USP_ERROR_CODE_INTERNAL_ERROR
#define UspErrorCode_INVALID_ARGUMENTS          USP_ERROR_CODE_INVALID_ARGUMENTS
#define UspErrorCode_RESOURCES_EXCEEDED         USP_ERROR_CODE_RESOURCES_EXCEEDED
#define UspErrorCode_PERMISSION_DENIED          USP_ERROR_CODE_PERMISSION_DENIED
#define UspErrorCode_INVALID_CONFIGURATION      USP_ERROR_CODE_INVALID_CONFIGURATION
#define UspErrorCode_INVALID_PATH_SYNTAX        USP_ERROR_CODE_INVALID_PATH_SYNTAX
#define UspErrorCode_PARAMETER_ACTION_FAILED    USP_ERROR_CODE_PARAMETER_ACTION_FAILED
#define UspErrorCode_UNSUPPORTED_PARAMETER      USP_ERROR_CODE_UNSUPPORTED_PARAMETER
#define UspErrorCode_INVALID_TYPE               USP_ERROR_CODE_INVALID_TYPE
#define UspErrorCode_INVALID_VALUE              USP_ERROR_CODE_INVALID_VALUE
#define UspErrorCode_NON_WRITABLE_PARAMETER     USP_ERROR_CODE_NON_WRITABLE_PARAMETER
#define UspErrorCode_VALUE_CONFLICT             USP_ERROR_CODE_VALUE_CONFLICT
#define UspErrorCode_OPERATION_ERROR            USP_ERROR_CODE_OPERATION_ERROR
#define UspErrorCode_OBJECT_DOES_NOT_EXIST      USP_ERROR_CODE_OBJECT_DOES_NOT_EXIST
#define UspErrorCode_OBJECT_COULD_NOT_BE_CREATED USP_ERROR_CODE_OBJECT_COULD_NOT_BE_CREATED
#define UspErrorCode_OBJECT_IS_NOT_A_TABLE      USP_ERROR_CODE_OBJECT_IS_NOT_A_TABLE
#define UspErrorCode_NON_CREATABLE_OBJECT       USP_ERROR_CODE_NON_CREATABLE_OBJECT
#define UspErrorCode_OBJECT_COULD_NOT_BE_UPDATED USP_ERROR_CODE_OBJECT_COULD_NOT_BE_UPDATED
#define UspErrorCode_REQUIRED_PARAMETER_FAILED  USP_ERROR_CODE_REQUIRED_PARAMETER_FAILED
#define UspErrorCode_COMMAND_FAILURE            USP_ERROR_CODE_COMMAND_FAILURE
#define UspErrorCode_COMMAND_CANCELED           USP_ERROR_CODE_COMMAND_CANCELED
#define UspErrorCode_DELETE_FAILURE             USP_ERROR_CODE_DELETE_FAILURE
#define UspErrorCode_DUPLICATE_KEY              USP_ERROR_CODE_DUPLICATE_KEY
#define UspErrorCode_INVALID_PATH               USP_ERROR_CODE_INVALID_PATH
#define UspErrorCode_INVALID_COMMAND_ARGUMENTS  USP_ERROR_CODE_INVALID_COMMAND_ARGUMENTS
#define UspErrorCode_VENDOR_DEFINED_MIN         USP_ERROR_CODE_VENDOR_DEFINED_MIN
#define UspErrorCode_VENDOR_DEFINED_MAX         USP_ERROR_CODE_VENDOR_DEFINED_MAX

/* ── Status codes ────────────────────────────────────────────────────────── */

#define USP_OK                  0
#define USP_ERR_NULL_POINTER    1
#define USP_ERR_INVALID_UTF8    2
#define USP_ERR_BUFFER_TOO_SMALL 3
#define USP_ERR_RUNTIME         4
#define USP_ERR_USP             5
#define USP_ERR_NOT_FOUND       6
#define USP_ERR_INVALID_ARGUMENT 7
#define USP_ERR_PANIC           8

/* ── Subscription notification type constants ─────────────────────────────── */

#define USP_SUBSCRIPTION_VALUE_CHANGE    0
#define USP_SUBSCRIPTION_OBJECT_CREATION 1
#define USP_SUBSCRIPTION_OBJECT_DELETION 2

/* ── Opaque handle type ───────────────────────────────────────────────────── */

/*
 * Opaque handle representing a USP controller session.
 * Created by usp_controller_new(), destroyed by usp_controller_free().
 * Must not be copied, moved, or accessed concurrently from multiple threads.
 */
typedef struct UspControllerHandle UspControllerHandle;

/*
 * Callback invoked when a USP notification arrives for a registered subscription.
 *
 * Invocation context: called from the library's internal background thread.
 * The callback MUST be thread-safe and MUST NOT call any usp_controller_*
 * functions (deadlock risk).
 *
 * user_data: the opaque pointer supplied to usp_controller_subscribe_*_and_get().
 *            The caller is responsible for ensuring user_data remains valid for
 *            the full lifetime of the subscription.
 */
typedef void (*UspNotificationCallback)(void *user_data);

/* ── Public C API ─────────────────────────────────────────────────────────── */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * usp_controller_new
 *
 * Create a new USP controller handle.
 *
 * Parameters:
 *   socket_path       – NUL-terminated filesystem path to the OB-USPA UNIX
 *                       domain socket (e.g. "/var/run/usp/broker_agent_path").
 *                       Must not be NULL.
 *   app_endpoint_id   – NUL-terminated TR-369 USP endpoint ID of this
 *                       application (e.g. "proto::myapp").  Sent as from_id
 *                       in every outgoing USP Record.  Must not be NULL.
 *   agent_endpoint_id – NUL-terminated TR-369 USP endpoint ID of the agent
 *                       (e.g. "proto::api-gateway").  Sent as to_id.
 *                       Must not be NULL; pass "" to address whichever agent
 *                       answers the UDS handshake.
 *   timeout_secs      – Per-request I/O timeout in seconds.  Pass 0 to use
 *                       the default (10 seconds).
 *
 * Returns:
 *   Non-NULL handle on success.  NULL if any argument is NULL, contains
 *   invalid UTF-8, or the internal runtime cannot be initialised.
 *
 * Ownership:
 *   The caller owns the returned handle and MUST release it with
 *   usp_controller_free() when it is no longer needed.
 *
 * Thread safety: NOT thread-safe.  Create one handle per thread or protect
 *   with an external lock.
 */
LIBUSP_API
struct UspControllerHandle *usp_controller_new(
    const char *socket_path,
    const char *app_endpoint_id,
    const char *agent_endpoint_id,
    uint64_t    timeout_secs);

/*
 * usp_controller_free
 *
 * Destroy a USP controller handle and release all associated resources.
 *
 * This function:
 *   – stops the internal background worker thread (blocking until it exits),
 *   – closes the UNIX domain socket connection,
 *   – frees all memory.
 *
 * Passing NULL is safe (no-op).
 * Passing the same handle twice is undefined behaviour.
 *
 * Thread safety: NOT thread-safe with respect to other calls on the same handle.
 */
LIBUSP_API
void usp_controller_free(struct UspControllerHandle *handle);

/*
 * usp_controller_get
 *
 * Send a USP GET request for a single data-model path.
 *
 * Parameters:
 *   handle        – non-NULL handle returned by usp_controller_new().
 *   path          – NUL-terminated data-model path to retrieve.
 *   out_value     – caller-supplied buffer to receive the NUL-terminated value.
 *                   May be NULL only if out_value_len is 0 (value is discarded).
 *   out_value_len – size of out_value in bytes, including space for the NUL.
 *
 * Returns:
 *   USP_OK              – success; out_value contains the value.
 *   USP_ERR_NOT_FOUND   – path was not present in the agent response.
 *   USP_ERR_BUFFER_TOO_SMALL – out_value_len is too small for the value.
 *   USP_ERR_USP         – agent returned an error (see usp_controller_last_error).
 *   USP_ERR_NULL_POINTER – handle or path is NULL.
 *
 * Blocking: yes, waits for the agent response (up to timeout_secs).
 * Callbacks: none.
 */
LIBUSP_API
int usp_controller_get(
    struct UspControllerHandle *handle,
    const char *path,
    char       *out_value,
    size_t      out_value_len);

/*
 * usp_controller_get_many
 *
 * Send a USP GET request for multiple data-model paths.
 *
 * Parameters:
 *   handle         – non-NULL handle.
 *   paths          – array of NUL-terminated path strings; must not be NULL.
 *   path_count     – number of entries in paths; must be > 0.
 *   out_result     – caller-supplied buffer for the encoded response text.
 *                    May be NULL only if out_result_len is 0 (response discarded).
 *   out_result_len – size of out_result in bytes.
 *
 * Response format: see header file comment above.
 *
 * Returns: USP_OK or an error code.
 * Blocking: yes.
 */
LIBUSP_API
int usp_controller_get_many(
    struct UspControllerHandle *handle,
    const char *const          *paths,
    size_t                      path_count,
    char                       *out_result,
    size_t                      out_result_len);

/*
 * usp_controller_get_many_depth
 *
 * Like usp_controller_get_many but sets the USP Get max_depth (0 = unlimited,
 * 1 = only the requested object's direct children).  Same response format.
 */
LIBUSP_API
int usp_controller_get_many_depth(
    struct UspControllerHandle *handle,
    const char *const          *paths,
    size_t                      path_count,
    uint32_t                    max_depth,
    char                       *out_result,
    size_t                      out_result_len);

/*
 * usp_controller_set
 *
 * Send a USP SET request to assign a value to a single data-model parameter.
 *
 * Parameters:
 *   handle – non-NULL handle.
 *   path   – NUL-terminated full parameter path (e.g. "Device.WiFi.SSID.1.SSID").
 *   value  – NUL-terminated new value string.
 *
 * Returns: USP_OK or an error code.
 * Blocking: yes.
 */
LIBUSP_API
int usp_controller_set(
    struct UspControllerHandle *handle,
    const char *path,
    const char *value);

/*
 * usp_controller_set_many
 *
 * Send a USP SET request to assign values to multiple data-model parameters.
 *
 * Parameters:
 *   handle        – non-NULL handle.
 *   paths         – array of NUL-terminated full parameter paths.
 *   values        – array of NUL-terminated value strings; parallel to paths.
 *   param_count   – number of entries; must be > 0.
 *   out_result    – caller-supplied buffer for the encoded response text.
 *   out_result_len – size of out_result.
 *
 * Response format: see header file comment above.
 *
 * Returns: USP_OK or an error code.
 * Blocking: yes.
 */
LIBUSP_API
int usp_controller_set_many(
    struct UspControllerHandle *handle,
    const char *const          *paths,
    const char *const          *values,
    size_t                      param_count,
    char                       *out_result,
    size_t                      out_result_len);

/*
 * usp_controller_operate
 *
 * Send a USP OPERATE request to invoke a data-model command.
 *
 * Parameters:
 *   handle         – non-NULL handle.
 *   command        – NUL-terminated command path, e.g. "Device.IP.Interface.1.Reset()".
 *   arg_names      – array of NUL-terminated input argument names.
 *                    May be NULL if arg_count is 0.
 *   arg_values     – array of NUL-terminated input argument values.
 *                    May be NULL if arg_count is 0.  Parallel to arg_names.
 *   arg_count      – number of input arguments.
 *   out_result     – caller-supplied buffer for the encoded response text.
 *   out_result_len – size of out_result.
 *
 * Response format: see header file comment above.
 *
 * Returns: USP_OK or an error code.
 * Blocking: yes.
 */
LIBUSP_API
int usp_controller_operate(
    struct UspControllerHandle *handle,
    const char                 *command,
    const char *const          *arg_names,
    const char *const          *arg_values,
    size_t                      arg_count,
    char                       *out_result,
    size_t                      out_result_len);

/*
 * usp_controller_subscribe_and_get
 *
 * Register a USP subscription for one path and perform an immediate GET.
 *
 * After the subscription is registered, the notification callback will be
 * invoked from the library's internal background thread each time an
 * unsolicited Notify message arrives for the subscription.
 *
 * Parameters:
 *   handle            – non-NULL handle.
 *   path              – NUL-terminated data-model path to subscribe on.
 *   notification_type – one of:
 *                         USP_SUBSCRIPTION_VALUE_CHANGE
 *                         USP_SUBSCRIPTION_OBJECT_CREATION
 *                         USP_SUBSCRIPTION_OBJECT_DELETION
 *   callback          – function called on each notification; may be NULL.
 *   user_data         – opaque pointer passed verbatim to callback.
 *                       Must remain valid until the handle is freed.
 *   out_result        – caller-supplied buffer for the GET response.
 *   out_result_len    – size of out_result.
 *
 * Returns: USP_OK or an error code.
 * Blocking: yes (blocks until subscription ADD and initial GET complete).
 * Callbacks: callback may be invoked asynchronously from a background thread
 *            AFTER this function returns.
 */
LIBUSP_API
int usp_controller_subscribe_and_get(
    struct UspControllerHandle *handle,
    const char                 *path,
    int                         notification_type,
    UspNotificationCallback     callback,
    void                       *user_data,
    char                       *out_result,
    size_t                      out_result_len);

/*
 * usp_controller_subscribe_many_and_get
 *
 * Register USP subscriptions for multiple paths and perform an immediate GET.
 *
 * Parameters:
 *   handle             – non-NULL handle.
 *   paths              – array of NUL-terminated paths; must not be NULL.
 *   notification_types – array of notification type ints; parallel to paths.
 *                        Must not be NULL.
 *   subscription_count – number of entries; must be > 0.
 *   callback           – function called on each notification; may be NULL.
 *   user_data          – opaque pointer passed verbatim to callback.
 *   out_result         – caller-supplied buffer for the GET response.
 *   out_result_len     – size of out_result.
 *
 * Returns: USP_OK or an error code.
 * Blocking: yes.
 * Callbacks: as for usp_controller_subscribe_and_get.
 */
LIBUSP_API
int usp_controller_subscribe_many_and_get(
    struct UspControllerHandle *handle,
    const char *const          *paths,
    const int                  *notification_types,
    size_t                      subscription_count,
    UspNotificationCallback     callback,
    void                       *user_data,
    char                       *out_result,
    size_t                      out_result_len);

/*
 * usp_controller_register
 *
 * Send a USP REGISTER request (not yet implemented; returns USP_ERR_USP).
 */
LIBUSP_API
int usp_controller_register(
    struct UspControllerHandle *handle,
    const char *obj);

/*
 * usp_controller_add
 *
 * Send a USP ADD request (not yet implemented; returns USP_ERR_USP).
 */
LIBUSP_API
int usp_controller_add(
    struct UspControllerHandle *handle,
    const char                 *obj,
    const char *const          *param_paths,
    const char *const          *param_values,
    size_t                      param_count);

/*
 * usp_controller_delete
 *
 * Send a USP DELETE request (not yet implemented; returns USP_ERR_USP).
 */
LIBUSP_API
int usp_controller_delete(
    struct UspControllerHandle *handle,
    const char *instance);

/*
 * usp_controller_get_supported_dm
 *
 * Send a USP GetSupportedDM request (not yet implemented; returns USP_ERR_USP).
 */
LIBUSP_API
int usp_controller_get_supported_dm(
    struct UspControllerHandle *handle,
    const char *obj);

/*
 * usp_controller_get_instances
 *
 * Send a USP GetInstances request (not yet implemented; returns USP_ERR_USP).
 */
LIBUSP_API
int usp_controller_get_instances(
    struct UspControllerHandle *handle,
    const char *obj);

/*
 * usp_controller_get_supported_protocol
 *
 * Send a USP GetSupportedProtocol request (not yet implemented; returns USP_ERR_USP).
 */
LIBUSP_API
int usp_controller_get_supported_protocol(
    struct UspControllerHandle *handle);

/*
 * usp_controller_set_timeout
 *
 * Override the per-request I/O timeout.
 *
 * Parameters:
 *   handle       – non-NULL handle.
 *   timeout_secs – new timeout in seconds; 0 = use default (10 seconds).
 *
 * Returns: USP_OK or USP_ERR_NULL_POINTER.
 */
LIBUSP_API
int usp_controller_set_timeout(
    struct UspControllerHandle *handle,
    uint64_t timeout_secs);

/*
 * usp_error_is_vendor_defined
 *
 * Return 1 if code is in the TR-369 vendor-defined range [7800, 7999],
 * 0 otherwise.  Does not require a handle.
 */
LIBUSP_API
int usp_error_is_vendor_defined(uint32_t code);

/*
 * usp_controller_last_error
 *
 * Retrieve the human-readable error string from the most recent error on this
 * handle.
 *
 * Parameters:
 *   handle       – non-NULL handle (may be const).
 *   out_error    – caller-supplied buffer to receive the NUL-terminated string.
 *                  Must not be NULL.
 *   out_error_len – size of out_error in bytes.
 *
 * Returns: USP_OK or an error code.
 */
LIBUSP_API
int usp_controller_last_error(
    const struct UspControllerHandle *handle,
    char   *out_error,
    size_t  out_error_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBUSPMTP_H */
