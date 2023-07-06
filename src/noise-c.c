#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "noise/protocol.h"

/* Message buffer for send/receive */
#define MAX_MESSAGE_LEN 4096
static uint8_t message[MAX_MESSAGE_LEN + 2];

int TestHandshake() {
    int err = noise_init();
    if (err != NOISE_ERROR_NONE) {
        noise_perror("Noise initialization failed", err);
        return 1;
    }

    NoiseHandshakeState *handshake;
    char *protocol = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
    err = noise_handshakestate_new_by_name
        (&handshake, protocol, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    char *prologue = "InkLinkv1";
    err = noise_handshakestate_set_prologue(handshake, prologue, strlen(prologue));
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    // The NN handshake only uses ephemeral keys, e.g.
      // -> e 
      // <- e, ee
    NoiseDHState *dh = noise_handshakestate_get_fixed_ephemeral_dh(handshake);
    int key_len = noise_dhstate_generate_keypair(dh);

    err = noise_handshakestate_start(handshake);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("start handshake", err);
        return 1;
    }
    
    int ok = 1;
    int action;
    NoiseBuffer mbuf;
    while (ok) {
        action = noise_handshakestate_get_action(handshake);
        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            /* Write the next handshake message with a zero-length payload */
            noise_buffer_set_output(mbuf, message + 2, sizeof(message) - 2);
            err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
            if (err != NOISE_ERROR_NONE) {
                noise_perror("write handshake", err);
                ok = 0;
                break;
            }
            message[0] = (uint8_t)(mbuf.size >> 8);
            message[1] = (uint8_t)mbuf.size;

            // TODO: THIS IS WHERE WE SEND THE MESSAGE TO THE SERVER
        } else if (action == NOISE_ACTION_READ_MESSAGE) {
            /* Read the next handshake message and discard the payload */

            // TODO: THIS IS WHERE WE LOAD THE MESSAGE FROM THE SERVER
            // message_size = echo_recv(fd, message, sizeof(message));
            // if (!message_size) {
            //     ok = 0;
            //     break;
            // }
            // noise_buffer_set_input(mbuf, message + 2, message_size - 2);
            // err = noise_handshakestate_read_message(handshake, &mbuf, NULL);
            // if (err != NOISE_ERROR_NONE) {
            //     noise_perror("read handshake", err);
            //     ok = 0;
            //     break;
            // }
        } else {
            /* Either the handshake has finished or it has failed */
            break;
        }
    }

    action = noise_handshakestate_get_action(handshake);
    if (ok &&  action != NOISE_ACTION_SPLIT) {
        int length = snprintf( NULL, 0, "action was %d", action );
        char* str = malloc( length + 1 );
        snprintf( str, length + 1, "%d", action );
        noise_perror(str, err);
        return 1;
    }

    NoiseCipherState *send_cipher = 0;
    NoiseCipherState *recv_cipher = 0;
    err = noise_handshakestate_split(handshake, &send_cipher, &recv_cipher);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("split to start data transfer", err);
        ok = 0;
    }

    // At this point, the handshake is complete and we can free the handshake state
    // and use the cipher states to send and receive messages.
    noise_handshakestate_free(handshake);
    handshake = 0;
    
    return 0;
}
