#include "protocol/internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <noise/protocol.h>

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 4096
static uint8_t message_buffer[MAX_MESSAGE_LEN];

#define ERROR_CODE_NOISE_INIT        0x01
#define ERROR_CODE_NEW_HANDSHAKE     0x02
#define ERROR_CODE_SET_PROLOGUE      0x03
#define ERROR_CODE_HANDSHAKE_START   0x04
#define ERROR_CODE_UNEXPECTED_ACTION 0x05
#define ERROR_CODE_WRITE_MESSAGE     0x06
#define ERROR_CODE_READ_MESSAGE      0x07
#define ERROR_CODE_SPLIT_FAILED      0x08
#define ERROR_CODE_XK                0x09
#define ERROR_CODE_IK                0x0A
#define ERROR_CODE_XX                0x0B
#define ERROR_CODE_IX                0x0C

// TODO: Fill this out with the state we need to serialize.
typedef struct {
    // Symmetric state
    uint8_t ck[64];
    uint8_t h[64];

} HandshakeState;

typedef struct {
    uint32_t error_code;
    size_t message_size;
    uint8_t *message;
    // TODO: Figure out how to do this correctly.
    // HandshakeState *hs;
} StartHandshakeResponse;

StartHandshakeResponse *start_handshake() {
    StartHandshakeResponse *resp = malloc(sizeof(StartHandshakeResponse));

    int err = noise_init();
    if (err != NOISE_ERROR_NONE) {
        noise_perror("Noise initialization failed", err);
        resp->error_code = ERROR_CODE_NOISE_INIT;
        return resp;
    }

    NoiseHandshakeState *handshake;
    char *protocol = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
    err = noise_handshakestate_new_by_name
        (&handshake, protocol, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        resp->error_code = ERROR_CODE_NEW_HANDSHAKE;
        return resp;
    }

    char *prologue = "InkLinkv1";
    err = noise_handshakestate_set_prologue(handshake, prologue, strlen(prologue));
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        resp->error_code = ERROR_CODE_SET_PROLOGUE;
        return resp;
    }

    // The NN handshake only uses ephemeral keys, e.g.
    //   -> e 
    //   <- e, ee
    // NoiseDHState *dh = noise_handshakestate_get_fixed_ephemeral_dh(handshake);
    // size_t key_len = noise_dhstate_generate_keypair(dh);

    err = noise_handshakestate_start(handshake);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("start handshake", err);
        resp->error_code = ERROR_CODE_HANDSHAKE_START;
        return resp;
    }
    
    int action = noise_handshakestate_get_action(handshake);
    if (action != NOISE_ACTION_WRITE_MESSAGE) {
        fprintf(stderr, "unexpected action %d\n", action);
        resp->error_code = ERROR_CODE_UNEXPECTED_ACTION;
        return resp;
    }

    /* Write the next handshake message with a zero-length payload */
    NoiseBuffer mbuf;
    noise_buffer_set_output(mbuf, message_buffer, sizeof(message_buffer));
    err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("write handshake", err);
        resp->error_code = ERROR_CODE_WRITE_MESSAGE;
        return resp;
    }

    resp->message_size = mbuf.size;
    resp->message = &message_buffer[0];
    resp->error_code = 0;
    // resp->handshake = handshake;

    return resp;
}

typedef struct {
    uint32_t error_code;
    size_t message_size;
    uint8_t *message;
    // TODO: Figure out how to do this correctly.
    // NoiseHandshakeState *handshake;
} ContinueHandshakeResponse;

ContinueHandshakeResponse *continue_handshake(uint8_t *message, size_t message_size) {
    ContinueHandshakeResponse *resp = malloc(sizeof(ContinueHandshakeResponse));

    int err = noise_init();
    if (err != NOISE_ERROR_NONE) {
        noise_perror("Noise initialization failed", err);
        resp->error_code = ERROR_CODE_NOISE_INIT;
        return resp;
    }

    NoiseHandshakeState *handshake;
    char *protocol = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
    err = noise_handshakestate_new_by_name
        (&handshake, protocol, NOISE_ROLE_RESPONDER);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        resp->error_code = ERROR_CODE_NEW_HANDSHAKE;
        return resp;
    }

    char *prologue = "InkLinkv1";
    err = noise_handshakestate_set_prologue(handshake, prologue, strlen(prologue));
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        resp->error_code = ERROR_CODE_SET_PROLOGUE;
        return resp;
    }

    // The NN handshake only uses ephemeral keys, e.g.
    //   -> e 
    //   <- e, ee
    // NoiseDHState *dh = noise_handshakestate_get_fixed_ephemeral_dh(handshake);
    // size_t key_len = noise_dhstate_generate_keypair(dh);

    err = noise_handshakestate_start(handshake);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("start handshake", err);
        resp->error_code = ERROR_CODE_HANDSHAKE_START;
        return resp;
    }

    // Our first action is to read the initiator's part of the handshake.
    int action = noise_handshakestate_get_action(handshake);
    if (action != NOISE_ACTION_READ_MESSAGE) {
        fprintf(stderr, "unexpected action %d\n", action);
        resp->error_code = ERROR_CODE_UNEXPECTED_ACTION;
        return resp;
    }

    NoiseBuffer mbuf;
    noise_buffer_set_input(mbuf, message, message_size);
    err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("read handshake", err);
        resp->error_code = ERROR_CODE_READ_MESSAGE;
        return resp;
    }
    
    // Our second action should be to write our responder's part of the handshake.
    action = noise_handshakestate_get_action(handshake);
    if (action != NOISE_ACTION_WRITE_MESSAGE) {
        fprintf(stderr, "unexpected action %d\n", action);
        resp->error_code = ERROR_CODE_UNEXPECTED_ACTION;
        return resp;
    }

    noise_buffer_set_output(mbuf, message_buffer, sizeof(message_buffer));
    err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("write handshake", err);
        resp->error_code = ERROR_CODE_WRITE_MESSAGE;
        return resp;
    }

    // Our third action should be to split into tx/rx cipher states.
    action = noise_handshakestate_get_action(handshake);
    if (action != NOISE_ACTION_SPLIT) {
        int length = snprintf( NULL, 0, "action was %d", action );
        char* str = malloc( length + 1 );
        snprintf( str, length + 1, "action was %d", action );
        noise_perror(str, err);
        resp->error_code = ERROR_CODE_UNEXPECTED_ACTION;
        return resp;
    }

    NoiseCipherState *send_cipher = 0;
    NoiseCipherState *recv_cipher = 0;
    err = noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("split to start data transfer", err);
        resp->error_code = ERROR_CODE_SPLIT_FAILED;
        return resp;
    }

    resp->message_size = mbuf.size;
    resp->message = &message_buffer[0];
    resp->error_code = 0;
    // resp->handshake = handshake;

    return resp;
}

int main() {
    start_handshake();
}
