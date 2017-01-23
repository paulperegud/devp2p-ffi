/// DevP2P-ffi -- C interface to Ethcore Parity's DEVP2P implementation
///
/// Notes:
/// * memory should be freed by side which allocated it
/// * contents of buffers passed around should be copied, since they will probably be freed
///   after return
/// * opaque pointers:
///   - service: represents DevP2P service; create, start, add subprotocol, do work, free
///   - io: network context; you can use it in callback where it is passed; don't save it for later!
///   - userdata: state of your subprotocol handler
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

    /* used as a value returned in errno */
    enum ErrCodes {
        ERR_OK = 0,
        ERR_UNKNOWN_PEER = 1,
        ERR_ERROR = 255
    };

    // callback types defined
    typedef void (*InitializeCB)(void* userdata, void* io);
    typedef void (*ConnectedCB)(void* userdata, void* io, size_t peer_id);
    typedef void (*ReadCB)(void* userdata, void* io,
                           size_t peer_id, uint8_t packet_id,
                           size_t ptr_len, uint8_t const* ptr);
    typedef void (*DisconnectedCB)(void* userdata, void* io,
                                   size_t peer_id);

    struct FFICallbacks {
        InitializeCB initialize;
        ConnectedCB connect;
        ReadCB read;
        DisconnectedCB disconnect;
    };

    // bind to localhost
    void* config_local();
    // bind to 0.0.0.0 with specified port
    void* config_with_port(uint16_t port);
    // creates service, returns opaque pointer to service
    void* network_service(void* config, uint8_t* errno);
    // consumes opaque pointer to service, frees it
    void network_service_free(void* service);

    // starts service, returns ErrCodes
    uint8_t network_service_start(void* service);

    // Adds subprotocol. Call only after network_service_start
    // returns ErrCodes
    uint8_t network_service_add_protocol(void* service,
                                         void* userdata,
                                         uint8_t* protocol_id,
                                         uint8_t max_packet_id,
                                         uint8_t* versions,
                                         size_t versions_len,
                                         struct FFICallbacks* callbacks
                                         );

    void protocol_send(void* service, uint8_t* protocol_id,
                       size_t peer_id, uint8_t packet_id,
                       char* buffer, size_t buffer_size);
    void protocol_reply(void* io, size_t peer_id, uint8_t packet_id,
                        uint8_t* buffer, size_t buffer_size);

    uint8_t peer_protocol_version(void* io, uint8_t* protocol_id,
                                  size_t peer_id, uint8_t* errno);

    int32_t network_service_add_reserved_peer(void* service, char const* node_name);

    uint8_t const* network_service_node_name(void* service);

#ifdef __cplusplus
}
#endif
