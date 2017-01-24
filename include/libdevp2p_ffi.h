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

    struct StrLen {
        size_t len;
        char* buff;
    };

    struct Configuration {
        struct StrLen* config_path;
        struct StrLen* net_config_path;
        struct StrLen* listen_address;
    };

    /* used as a value returned in errno and everywhere where function returns uint8_t */
    enum ErrCodes {
        ERR_OK = 0,
        ERR_UNKNOWN_PEER = 1,
        ERR_AUTH = 2,
        ERR_EXPIRED = 3,
        ERR_BADPROTOCOL = 4,
        ERR_PEERNOTFOUND = 5,
        ERR_DISCONNECTED = 19, // 10..19
        ERR_UTIL = 29, // 20..29
        ERR_IO = 39, // 30..39
        ERR_ADDRESSPARSE = 49, // 40..49
        ERR_ADDRESSRESOLVE = 59, // 50..59
        ERR_STDIO = 69 // 60..69
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

    // CONFIGURATION
    // bind to localhost
    void* config_local();
    // bind to 0.0.0.0 with specified port
    void* config_with_port(uint16_t port);
    // advanced configuration
    void* config_detailed(struct Configuration*);

    void unpack_and_print(struct StrLen*, struct StrLen*);


    // SERVICE
    // creates service, returns opaque pointer to service
    void* network_service(void* config, uint8_t* errno);
    // consumes opaque pointer to service, frees it
    void network_service_free(void* service);
    // starts service, returns ErrCodes
    uint8_t network_service_start(void* service);

    // PROTOCOLS
    // Adds subprotocol. Call only after network_service_start. Returns ErrCodes
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
    uint8_t protocol_reply(void* io, size_t peer_id, uint8_t packet_id,
                           uint8_t* buffer, size_t buffer_size);
    uint8_t peer_protocol_version(void* io, uint8_t* protocol_id,
                                  size_t peer_id, uint8_t* errno);

    // OTHER
    int32_t network_service_add_reserved_peer(void* service, char const* node_name);
    uint8_t const* network_service_node_name(void* service);

#ifdef __cplusplus
}
#endif
