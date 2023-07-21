#include "noise/protocol/handshakestate.h"
#include "protocol/internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <noise/protocol.h>

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 32768
static uint8_t message_buffer[MAX_MESSAGE_LEN];

#define ERROR_CODE_NOISE_INIT        0x01
#define ERROR_CODE_NEW_HANDSHAKE     0x02
#define ERROR_CODE_SET_PROLOGUE      0x03
#define ERROR_CODE_HANDSHAKE_START   0x04
#define ERROR_CODE_UNEXPECTED_ACTION 0x05
#define ERROR_CODE_WRITE_MESSAGE     0x06
#define ERROR_CODE_READ_MESSAGE      0x07
#define ERROR_CODE_SPLIT_FAILED      0x08
#define ERROR_CODE_NO_GLOBAL_STATE   0x09
#define ERROR_CODE_ENCRYPT_FAILED    0x0A
#define ERROR_CODE_DECRYPT_FAILED    0x0B
#define ERROR_CODE_BAD_PSK           0x0C
#define ERROR_CODE_SET_PSK           0x0D
#define ERROR_CODE_CS_EXPORT         0x0E
#define ERROR_CODE_CS_IMPORT         0x0F

// TODO: Remove this egregious hack, it's just to test the handshake before we have support for serializing/saving handshake data.
static NoiseHandshakeState *global_handshake;

typedef struct {
    uint32_t error_code;

    // Handshake data, to be sent to responder
    size_t message_size;
    uint8_t *message;

    // Serialized handshake state, needed for finish_handshake
    size_t handshake_state_size;
    uint8_t *handshake_state;
} StartHandshakeResponse;

StartHandshakeResponse *start_handshake(uint8_t *psk, size_t psk_size, uint8_t *payload, size_t payload_size) {
    StartHandshakeResponse *resp = malloc(sizeof(StartHandshakeResponse));

    if (psk_size != NOISE_PSK_LEN) {
        noise_perror("PSK had wrong length", NOISE_ERROR_INVALID_LENGTH);
        resp->error_code = ERROR_CODE_BAD_PSK;
        return resp;
    }

    int err = noise_init();
    if (err != NOISE_ERROR_NONE) {
        noise_perror("Noise initialization failed", err);
        resp->error_code = ERROR_CODE_NOISE_INIT;
        return resp;
    }

    NoiseHandshakeState *handshake;
    char *protocol = "NoisePSK_NN_25519_ChaChaPoly_BLAKE2s";
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

    err = noise_handshakestate_set_pre_shared_key(handshake, psk, psk_size);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        resp->error_code = ERROR_CODE_SET_PSK;
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
    NoiseBuffer mbuf_payload;
    noise_buffer_set_input(mbuf_payload, payload, payload_size);
    noise_buffer_set_output(mbuf, message_buffer, sizeof(message_buffer));
    err = noise_handshakestate_write_message(handshake, &mbuf, &mbuf_payload);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("write handshake", err);
        resp->error_code = ERROR_CODE_WRITE_MESSAGE;
        return resp;
    }

    resp->message_size = mbuf.size;
    resp->message = &message_buffer[0];
    resp->error_code = 0;
    // TODO:
    // resp->handshake_state_size = ??
    // resp->handshake_state = ??

    global_handshake = handshake;

    return resp;
}

typedef struct {
    uint32_t error_code;

    // Handshake data, to be sent to initiator
    size_t message_size;
    uint8_t *message;

    // This is actual user message data, not Noise handshake data.
    // It's the user info the initiator sent in start_handshake.
    size_t payload_size;
    uint8_t *payload;

    // Serialized send cipher state, needed for encrypt_message
    size_t send_cipher_state_size;
    uint8_t *send_cipher_state;

    // Serialized recv cipher state, needed for decrypt_message
    size_t recv_cipher_state_size;
    uint8_t *recv_cipher_state;
} ContinueHandshakeResponse;

ContinueHandshakeResponse *continue_handshake(uint8_t *message, size_t message_size, uint8_t *psk, size_t psk_size, uint8_t *payload, size_t payload_size) {
    ContinueHandshakeResponse *resp = malloc(sizeof(ContinueHandshakeResponse));

    int err = noise_init();
    if (err != NOISE_ERROR_NONE) {
        noise_perror("Noise initialization failed", err);
        resp->error_code = ERROR_CODE_NOISE_INIT;
        return resp;
    }

    NoiseHandshakeState *handshake;
    char *protocol = "NoisePSK_NN_25519_ChaChaPoly_BLAKE2s";
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

    err = noise_handshakestate_set_pre_shared_key(handshake, psk, psk_size);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        resp->error_code = ERROR_CODE_SET_PSK;
        return resp;
    }

    // The NNpsk0 handshake looks like.
    //   -> psk, e 
    //   <- e, ee
    //
    // So here, we read the initator's message, respond with our own, and we're ready to send messages.

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

    NoiseBuffer mbuf_payload;
    NoiseBuffer mbuf;
    noise_buffer_set_input(mbuf, message, message_size);
    noise_buffer_set_output(mbuf_payload, message_buffer, sizeof(message_buffer));
    err = noise_handshakestate_read_message(handshake, &mbuf, &mbuf_payload);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("read handshake", err);
        resp->error_code = ERROR_CODE_READ_MESSAGE;
        return resp;
    }

    // Copy the payload to something we can return so we can reuse the buffer.
    size_t out_payload_size = mbuf_payload.size;
    uint8_t *out_payload = malloc( sizeof( uint8_t ) * out_payload_size );
    memcpy(out_payload, message_buffer, out_payload_size);
    
    // Our second action should be to write our responder's part of the handshake, along with our payload.
    action = noise_handshakestate_get_action(handshake);
    if (action != NOISE_ACTION_WRITE_MESSAGE) {
        fprintf(stderr, "unexpected action %d\n", action);
        resp->error_code = ERROR_CODE_UNEXPECTED_ACTION;
        return resp;
    }

    noise_buffer_set_input(mbuf_payload, payload, payload_size);
    noise_buffer_set_output(mbuf, message_buffer, sizeof(message_buffer));
    err = noise_handshakestate_write_message(handshake, &mbuf, &mbuf_payload);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("write handshake", err);
        resp->error_code = ERROR_CODE_WRITE_MESSAGE;
        return resp;
    }

    // Our third action should be to split into tx/rx cipher states.
    action = noise_handshakestate_get_action(handshake);
    if (action != NOISE_ACTION_SPLIT) {
        fprintf(stderr, "unexpected action %d\n", action);
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

    NoiseCipherStateExport send_exp;
    NoiseCipherStateExport recv_exp;
    err = noise_cipherstate_export(send_cipher, &send_exp);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("failed to export send cipher state", err);
        resp->error_code = ERROR_CODE_CS_EXPORT;
        return resp;
    }
    err = noise_cipherstate_export(recv_cipher, &recv_exp);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("failed to export recv cipher state", err);
        resp->error_code = ERROR_CODE_CS_EXPORT;
        return resp;
    }

    resp->message_size = mbuf.size;
    resp->message = &message_buffer[0];

    resp->payload = out_payload;
    resp->payload_size = out_payload_size;

    resp->send_cipher_state_size = send_exp.data_size;
    resp->send_cipher_state = send_exp.data;

    resp->recv_cipher_state_size = recv_exp.data_size;
    resp->recv_cipher_state = recv_exp.data;

    resp->error_code = 0;

   return resp;
}

typedef struct {
    uint32_t error_code;

    // This is actual user message data, not Noise handshake data.
    // It's the user info the responder sent back in continue_handshake.
    size_t payload_size;
    uint8_t *payload;

    // Serialized send cipher state, needed for encrypt_message
    size_t send_cipher_state_size;
    uint8_t *send_cipher_state;

    // Serialized recv cipher state, needed for decrypt_message
    size_t recv_cipher_state_size;
    uint8_t *recv_cipher_state;
} FinishHandshakeResponse;

FinishHandshakeResponse *finish_handshake(uint8_t *handshake_state, size_t handshake_state_size, uint8_t *message, size_t message_size) {
    FinishHandshakeResponse *resp = malloc(sizeof(FinishHandshakeResponse));

    if (!global_handshake) {
        resp->error_code = ERROR_CODE_NO_GLOBAL_STATE;
        return resp;
    }

    // TODO: Use handshake_state instead
    NoiseHandshakeState *handshake = global_handshake;

    // Our first action is to read the responder's part of the handshake.
    int action = noise_handshakestate_get_action(handshake);
    if (action != NOISE_ACTION_READ_MESSAGE) {
        fprintf(stderr, "unexpected action %d\n", action);
        resp->error_code = ERROR_CODE_UNEXPECTED_ACTION;
        return resp;
    }

    NoiseBuffer mbuf_payload;
    NoiseBuffer mbuf;
    noise_buffer_set_input(mbuf, message, message_size);
    noise_buffer_set_output(mbuf_payload, message_buffer, sizeof(message_buffer));
    int err = noise_handshakestate_read_message(handshake, &mbuf, &mbuf_payload);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("read handshake", err);
        resp->error_code = ERROR_CODE_READ_MESSAGE;
        return resp;
    }
    
    // Our second action should be to split into tx/rx cipher states.
    action = noise_handshakestate_get_action(handshake);
    if (action != NOISE_ACTION_SPLIT) {
        fprintf(stderr, "unexpected action %d\n", action);
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

    NoiseCipherStateExport send_exp;
    NoiseCipherStateExport recv_exp;
    err = noise_cipherstate_export(send_cipher, &send_exp);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("failed to export send cipher state", err);
        resp->error_code = ERROR_CODE_CS_EXPORT;
        return resp;
    }
    err = noise_cipherstate_export(recv_cipher, &recv_exp);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("failed to export recv cipher state", err);
        resp->error_code = ERROR_CODE_CS_EXPORT;
        return resp;
    }

    resp->payload_size = mbuf_payload.size;
    resp->payload = &message_buffer[0];

    resp->send_cipher_state_size = send_exp.data_size;
    resp->send_cipher_state = send_exp.data;

    resp->recv_cipher_state_size = recv_exp.data_size;
    resp->recv_cipher_state = recv_exp.data;

    resp->error_code = 0;

    return resp;
}

typedef struct {
    uint32_t error_code;

    size_t message_size;
    uint8_t *message;

    size_t send_cipher_state_size;
    uint8_t *send_cipher_state;
} EncryptMessageResponse;

EncryptMessageResponse *encrypt_message(uint8_t *cipher_state, size_t cipher_state_size, uint8_t *message, size_t message_size) {
    EncryptMessageResponse *resp = malloc(sizeof(EncryptMessageResponse));

    NoiseCipherState *send_cipher = 0;
    int err = noise_cipherstate_import(cipher_state, cipher_state_size, &send_cipher);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("import failed", err);
        resp->error_code = ERROR_CODE_CS_IMPORT;
        return resp;
    }

    NoiseBuffer mbuf;
    memcpy(message_buffer, message, message_size);
    noise_buffer_set_inout(mbuf, message_buffer, message_size, sizeof(message_buffer));
    err = noise_cipherstate_encrypt(send_cipher, &mbuf);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("encryption failed", err);
        resp->error_code = ERROR_CODE_ENCRYPT_FAILED;
        return resp;
    }

    NoiseCipherStateExport send_exp;
    err = noise_cipherstate_export(send_cipher, &send_exp);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("failed to send_export send cipher state", err);
        resp->error_code = ERROR_CODE_CS_EXPORT;
        return resp;
    }
   
    resp->message_size = mbuf.size;
    resp->message = mbuf.data;

    resp->send_cipher_state_size = send_exp.data_size;
    resp->send_cipher_state = send_exp.data;

    resp->error_code = 0;

    return resp;
}

typedef struct {
    uint32_t error_code;
    size_t message_size;
    uint8_t *message;

    size_t recv_cipher_state_size;
    uint8_t *recv_cipher_state;
} DecryptMessageResponse;

DecryptMessageResponse *decrypt_message(uint8_t *cipher_state, size_t cipher_state_size, uint8_t *message, size_t message_size) {
    DecryptMessageResponse *resp = malloc(sizeof(DecryptMessageResponse));

    NoiseCipherState *recv_cipher = 0;
    int err = noise_cipherstate_import(cipher_state, cipher_state_size, &recv_cipher);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("import failed", err);
        resp->error_code = ERROR_CODE_CS_IMPORT;
        return resp;
    }

    NoiseBuffer mbuf;
    memcpy(message_buffer, message, message_size);
    noise_buffer_set_inout(mbuf, message_buffer, message_size, sizeof(message_buffer));
    err = noise_cipherstate_decrypt(recv_cipher, &mbuf);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("decryption failed", err);
        resp->error_code = ERROR_CODE_DECRYPT_FAILED;
        return resp;
    }

    NoiseCipherStateExport recv_exp;
    err = noise_cipherstate_export(recv_cipher, &recv_exp);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("failed to export recv cipher state", err);
        resp->error_code = ERROR_CODE_CS_EXPORT;
        return resp;
    }
   
    resp->message_size = mbuf.size;
    resp->message = mbuf.data;

    resp->recv_cipher_state_size = recv_exp.data_size;
    resp->recv_cipher_state = recv_exp.data;

    resp->error_code = 0;

    return resp;
}

int main() {
    // start_handshake();
}
