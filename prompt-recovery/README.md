# TDX Prompt Recovery Attack PoC

This attack leaks LLM prompts from a [llama.cpp](https://github.com/ggml-org/llama.cpp) instance running in a TDX CVM in a single shot.

**NOTE**: This is not an end-to-end exploit. The attack requires a special cooperating victim that gives it knowledge about the token layout in memory.

## Running the attack
### Reference Platform
* Host:
   * CPU: **Intel Xeon Gold 6526Y (Emerald Rapids)**
   * Kernel: **6.8.0-1015-intel**
   * TDX module: **attributes 0x0, vendor_id 0x8086, major_version 1, minor_version 5, build_date 20240407, build_num 744**
* Guest CVM:
   * Victim: Our llama.cpp fork (based on v0.18.0)
   * Kernel: **6.11.0-14-generic**, set up with [Ubuntu 24.04 for TDX](https://github.com/canonical/tdx)
   * Model [llama 3.2. 1B Q8_0](https://huggingface.co/unsloth/Llama-3.2-1B-Instruct-GGUF/blob/main/Llama-3.2-1B-Instruct-Q8_0.gguf), SHA256 `3f87a880027e7b`

### Setting up the cooperating victim
First, ensure that the host can reach the victim with TCP. The attack is hard-coded to connect to `localhost:12123`. This port should be forwarded from the guest CVM, i.e., the attacker connecting to `localhost:12123` on the host should be able to reach a victim listening on `0.0.0.0:12123` in the CVM.
Then, build the victim in [llama.cpp fork](https://github.com/tristan-hornetz/llama.cpp) in the CVM (see the regular llama.cpp repo for build instructions).
The victim should be located at `build/bin/llama-simple-chat-victim`. Start it as follows:
```shell
sudo build/bin/llama-simple-chat-victim -m <model.gguf>
```
The victim will wait for the attacker to connect.

### Running the attack
You can build the attacker by running `make` in this directory. While the victim is listening, run
```shell
sudo ./recover-prompt <model.gguf> [-v]
```
Ensure that the `tdxutils` kernel module is loaded and that the model file matches the victim's.
Specifying `-v` as the final parameter will cause the attack to print a variety of optional debug information.

The expected output is a series of different reconstructions of the prompt. They will likely not be 100% accurate.

## How it works
### Vulnerable Code
We attack a hash map in llama.cpp's tokenization routine, specifically an instance of `std::unordered_map<std::string, unsigned long>` from the C++ standard library (the vulnerable lookup is [here](https://github.com/ggml-org/llama.cpp/blob/381174bbdaf10d6a80dc2099f284b20544d86962/src/llama-vocab.cpp#L2897)).
The target hash map is used to translate string fragments from the prompt into token IDs for the LLM inference.
This works by hashing the strings, and using the hash as an index into an array of *buckets*, which are implemented as linked lists.
If the token corresponding to a specific string fragment exists, it will be part of the linked list at its hash's offset.
Once the correct linked list has been located, the victim traverses it until the token is found.
Both the hash-based indexing into the array of linked lists and the list's traversal are data-dependent memory lookups that we can observe with side-channels.
Hence, we can identify the individual prompt fragments, and recover the prompt from them.

### Getting memory access traces
The PoC uses the page table attack for synchronization, and a TSX-based primitive for monitoring the victim's cache state.

During setup, we split the **target pages** containing the buckets into 4kB pages, and block them.
Additionally, we block a **synchronization page**, which is *always* accessed *after* a target page is accessed.
For the PoC, this is the page containing the hash map's high-level data structure (i.e., identified by `&map` in C++ if `map` is the target hash map).
Alternatively, the synchronization page could also be a code page that is executed after the lookup is completed.

The attacker then waits for the CVM to access the blocked pages.
When a target page is accessed, we simply unblock it to allow the victim to access it.
Right afterward, the victim should access the synchronization page.
When this happens, we use our TSX-based primitive to check which cache lines in the previously accessed target page the CVM accessed.
We record them and re-block the target page.
This results in a trace of target page accesses and a list of cache lines that were accessed in each page access.


### Recovering the Prompt
When looking at the memory access traces, we see that in most cases, the CVM touches multiple tokens when accessing a single page.
However, only one of them is correct.
Therefore, the attack assigns each token in a page an **confidence score**, which provides a rough measure of how likely a token is deemed to be correct.
This score is based on multiple heuristics.
For instance, if we can observe a linked list being traversed, we can infer that the token at which the traversal stops is part of the prompt.
We also observe that between two correct token accesses, there is usually an access to a page holding no correct token, allowing us to de-prioritize accesses before and after accesses with a high confidence score.
Specify `-v` when running the attack to see all recorded cache line accesses with their confidence scores.
All tokens with a confidence score exceeding a given threshold are considered part of the prompt.
This already allows us to reconstruct the prompt with some accuracy.

Finally, to boost our accuracy further, we can utilize a quirk in the victim's implementation. On a high level, the code performing the tokenization looks as follows:
```c++
// tokenize the prompt
const int n_prompt_tokens = -llama_tokenize(vocab, prompt.c_str(), prompt.size(), NULL, 0, is_first, true);
std::vector<llama_token> prompt_tokens(n_prompt_tokens);
if (llama_tokenize(vocab, prompt.c_str(), prompt.size(), prompt_tokens.data(), prompt_tokens.size(), is_first, true) < 0) {
   GGML_ABORT("failed to tokenize the prompt\n");
}
```

Note that the victim calls `llama_tokenize` twice, which means that we can observe two tokenizations for the same prompt in a single shot.
Hence, as the final step, the PoC merges the results from both tokenizations into one.
For this, it uses both a *pessimistic* strategy, which discards tokens that were only observed in one of the two runs, and an *optimistic* strategy, which preserves those tokens.
The results of both strategies are printed as the final output.
