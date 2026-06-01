#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct program_header {
    uint32_t magic;
    uint32_t entry;
    uint32_t size;
    char     name[32];
};

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input.elf> <output.bin> [name]\n", argv[0]);
        return 1;
    }

    const char *input = argv[1];
    const char *output = argv[2];
    const char *name = (argc > 3) ? argv[3] : "";

    FILE *fin = fopen(input, "rb");
    if (!fin) {
        perror("open input");
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 1024*1024) {
        fprintf(stderr, "Bad input size\n");
        fclose(fin);
        return 1;
    }

    uint8_t *data = malloc(fsize);
    if (fread(data, 1, fsize, fin) != (size_t)fsize) {
        perror("read");
        free(data);
        fclose(fin);
        return 1;
    }
    fclose(fin);

    struct program_header hdr = {0};
    hdr.magic = 0x55524F48;
    hdr.entry = 0;
    hdr.size  = fsize;
    strncpy(hdr.name, name, 31);

    FILE *fout = fopen(output, "wb");
    if (!fout) {
        perror("open output");
        free(data);
        return 1;
    }

    fwrite(&hdr, 1, sizeof(hdr), fout);
    fwrite(data, 1, fsize, fout);
    fclose(fout);

    free(data);
    printf("Created %s (size=%ld, name='%s')\n", output, fsize, name);
    return 0;
}
