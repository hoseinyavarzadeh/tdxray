#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <llama.h>

#include "libtokenize.h"

static llama_context *ctx = nullptr;
static llama_model* model = nullptr;
static const llama_vocab * vocab = nullptr;

extern "C" void libtokenize_free_string(const char* str) {
    delete [] str;
}

extern "C" void libtokenize_free_tokens(int32_t* tokens) {
    delete [] tokens;
}

extern "C" unsigned long libtokenize_get_tokens(const char* prompt_ptr, int32_t** tokens_out) {
    if (ctx == nullptr || model == nullptr)
        return -1;

    auto prompt = std::string(prompt_ptr);

    const bool model_wants_add_bos = llama_vocab_get_add_bos(vocab);
    const bool add_bos = model_wants_add_bos;
    const bool parse_special = true;

    auto num_tokens = -llama_tokenize(vocab, prompt_ptr, strlen(prompt_ptr), nullptr, 0, add_bos, parse_special);
    *tokens_out = new int32_t[num_tokens];
    llama_tokenize(vocab, prompt_ptr, strlen(prompt_ptr), *tokens_out, num_tokens, add_bos, parse_special);

    return num_tokens;
}

extern "C" const char* libtokenize_tokens_to_string(const int32_t* tokens, unsigned long num_tokens) {

    auto len = -llama_detokenize(vocab, tokens, num_tokens, nullptr, 0, true, true);
    auto ret = new char[len];
    llama_detokenize(vocab, tokens, num_tokens, ret, len, true, true);

    return ret;
}

extern "C" int libtokenize_init(const char* model_path) {
    llama_backend_init();

    llama_model_params model_params = llama_model_default_params();
    model_params.vocab_only = true;
    model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        fprintf(stderr, "Error: could not load model from file '%s'.\n", model_path);
        return -1;
    }

    vocab = llama_model_get_vocab(model);

    llama_context_params ctx_params = llama_context_default_params();
    ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        fprintf(stderr, "Error: could not create context.\n");
        return -1;
    }

    return 0;
}

extern "C" void libtokenize_exit(void) {
    if (ctx)
        llama_free(ctx);
    if (model)
        llama_model_free(model);

    ctx = nullptr;
    model = nullptr;
}
