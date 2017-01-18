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

    typedef void (*InitializeCB)(void* ud, void* io);
    typedef void (*ConnectedCB)(void* ud, void* io, size_t peer_id);
    typedef void (*ReadCB)(void* ud, void* io,
                           size_t peer_id, uint8_t packet_id,
                           size_t len, uint8_t const* ptr);
    typedef void (*DisconnectedCB)(void* ud, void* io,
                                   size_t peer_id);

    struct FFICallbacks {
        InitializeCB initialize;
        ConnectedCB connect;
        ReadCB read;
        DisconnectedCB disconnect;
    };

    // return service
    void* network_service(uint8_t* errno);
    // consumes service
    void network_service_free(void* service);

    uint8_t network_service_start(void* service);

    // Adds subprotocol. Call only after network_service_start
    // Returns handler
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
                       char* buffer, size_t size);
    void protocol_reply(void* io, size_t peer_id, uint8_t packet_id,
                        uint8_t* buffer, size_t size);

    uint8_t peer_protocol_version(void* io,
                                  uint8_t* protocol_id,
                                  size_t peer_id, uint8_t* errno);

    int32_t network_service_add_reserved_peer(void* service, char const* node_name);

    uint8_t const* network_service_node_name(void* service);

    int32_t say_hello(int32_t(*func)(int32_t));

#ifdef __cplusplus
}
#endif
