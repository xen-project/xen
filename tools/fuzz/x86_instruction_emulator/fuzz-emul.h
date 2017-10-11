#ifndef FUZZ_EMUL_H
# define FUZZ_EMUL_H

extern int LLVMFuzzerInitialize(int *argc, char ***argv);
extern int LLVMFuzzerTestOneInput(const uint8_t *data_p, size_t size);
extern unsigned int fuzz_minimal_input_size(void);

#define INPUT_SIZE  4096

#endif /* ifdef FUZZ_EMUL_H */
