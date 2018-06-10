#include "test.h"

static int my_argon2_compare(const uint8_t* b1,const uint8_t* b2, size_t len);
static int my_argon2_ctx(argon2_context* context, argon2_type type);
static int my_argon2_verify_ctx(argon2_context* context, const char* hash, argon2_type type);

verify_result_t verify_high_level(verify_input_t* input)
{
    int err = argon2_verify(
        /* const char* encoded */ input->encoded,
        /* const void* pwd */ (void*)(input->password),
        /* const size_t pwdlen */ input->password_len,
        /* argon2_type type */ input->variant
    );
    verify_result_t output = {};
    output.err = err;
    if (err == ARGON2_OK) {
        output.is_valid = true;
        return output;
    } else {
        output.is_valid = false;
        return output;
    }
}

verify_result_t verify_low_level(verify_input_t* input)
{
    verify_result_t output = {};
    if (input->password_len > ARGON2_MAX_PWD_LENGTH) {
        output.err = ARGON2_PWD_TOO_LONG;
        output.is_valid = false;
        return output;
    }
    if (input->encoded == NULL) {
        output.err = ARGON2_DECODING_FAIL;
        output.is_valid = false;
        return output;
    }
    size_t encoded_len = strlen(input->encoded);
    if (encoded_len > UINT32_MAX) {
        output.err = ARGON2_DECODING_FAIL;
        output.is_valid = false;
        return output;
    }

    argon2_context ctx = {};
    ctx.saltlen = (uint32_t)encoded_len;
    ctx.outlen = (uint32_t)encoded_len;

    ctx.salt = (uint8_t*)malloc(ctx.saltlen);
    ctx.out = (uint8_t*)malloc(ctx.outlen);
    if (ctx.salt == NULL || ctx.out == NULL) {
        free(ctx.out);
        free(ctx.salt);
        output.err = ARGON2_MEMORY_ALLOCATION_ERROR;
        output.is_valid = false;
        return output;
    }

    ctx.pwd = (uint8_t*)(input->password);
    ctx.pwdlen = (uint32_t)(input->password_len);

    int err = decode_string( // Note: Located in encoding.c
        /* argon2_context* ctx */ &ctx,
        /* const char* str */ input->encoded,
        /* argon2_type type */ input->variant
    );
    if (err != ARGON2_OK) {
        free(ctx.out);
        free(ctx.salt);
        output.err = err;
        output.is_valid = false;
        return output;
    }

    uint8_t* desired_result = ctx.out;
    ctx.out = (uint8_t*)malloc(ctx.outlen);
    if (ctx.out == NULL) {
        free(ctx.out);
        free(ctx.salt);
        free(desired_result);
        output.err = ARGON2_MEMORY_ALLOCATION_ERROR;
        output.is_valid = false;
        return output;
    }

    // TODO: This is my code
    ctx.ad = input->additional_data;
    ctx.adlen = (size_t)(input->additional_data_len);
    ctx.secret = input->secret_key;
    ctx.secretlen = (size_t)(input->secret_key_len);

    err = my_argon2_verify_ctx(
        /* argon2_context* context */ &ctx,
        /* const char* encoded */ (char *)desired_result,
        /* argon2_type variant */ input->variant
    );
    if (err != ARGON2_OK) {
        free(ctx.out);
        free(ctx.salt);
        free(desired_result);
        output.err = err;
        output.is_valid = false;
        return output;
    }

    free(ctx.out);
    free(ctx.salt);
    free(desired_result);
    output.err = ARGON2_OK;
    output.is_valid = true;
    return output;
}

// Helper functions

static int my_argon2_verify_ctx(
    argon2_context* context,
    const char* encoded,
    argon2_type variant
) {
    int err = my_argon2_ctx(
        /* argon2_context* context */ context,
        /* argon2_type variant */ variant
    );
    if (err != ARGON2_OK) {
        return err;
    }
    err = my_argon2_compare(
        /* const uint8_t* b1 */ (uint8_t*)encoded,
        /* const uint8_t* b2 */ context->out,
        /* size_t len */ (size_t)(context->outlen)
    );
    if (err != 0) {
        return ARGON2_VERIFY_MISMATCH;
    }
    return ARGON2_OK;
}

static int my_argon2_ctx(
    argon2_context* context,
    argon2_type variant
) {
    /* 1. Validate inputs */
    int err = validate_inputs(context); // Note: Located in core.c
    if (err != ARGON2_OK) {
        return err;
    }
    if (Argon2_d != variant && Argon2_i != variant && Argon2_id != variant) {
        return ARGON2_INCORRECT_TYPE;
    }

    /* 2. Align memory size */
    uint32_t memory_blocks = context->m_cost;
    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }
    uint32_t segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

    argon2_instance_t instance = {};
    instance.version = context->version;
    instance.memory = NULL;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.threads = context->threads;
    instance.type = variant;
    if (instance.threads > instance.lanes) {
        instance.threads = instance.lanes;
    }

    /* 3. Initialization: Hashing inputs, allocating memory, filling first blocks */
    err = initialize(&instance, context); // Note: Located in core.c
    if (err != ARGON2_OK) {
        return err;
    }

    /* 4. Filling memory */
    err = fill_memory_blocks(&instance); // Note: Located in core.c
    if (err != ARGON2_OK) {
        return err;
    }

    /* 5. Finalization */
    finalize(context, &instance); // Note: Located in core.c

    return ARGON2_OK;
}

static int my_argon2_compare(
    const uint8_t* b1,
    const uint8_t* b2,
    size_t len
) {
    size_t i;
    uint8_t d = 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (int)((1 & ((d - 1) >> 8)) - 1);
}

