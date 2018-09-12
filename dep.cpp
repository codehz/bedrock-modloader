#include <elf.h>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

std::vector<fs::path> getDependencies(fs::path path) {
  Elf64_Ehdr header;
  auto file = fopen(path.c_str(), "r");
  if (file == nullptr) {
    perror("ModLoader: Failed to open mod");
    return {};
  }
  if (fread(&header, sizeof(header), 1, file) != 1) {
    perror("ModLoader: Failed to read mod header");
    fclose(file);
    return {};
  }
  fseek(file, (long)header.e_phoff, SEEK_SET);
  char phdr[header.e_phentsize * header.e_phnum];
  if (fread(phdr, header.e_phentsize, header.e_phnum, file) != header.e_phnum) {
    perror("ModLoader: Failed to read phnum");
    fclose(file);
    return {};
  }
  Elf64_Phdr *dynamicEntry = nullptr;
  for (int i = 0; i < header.e_phnum; i++) {
    Elf64_Phdr &entry = *((Elf64_Phdr *)&phdr[header.e_phentsize * i]);
    if (entry.p_type == PT_DYNAMIC) dynamicEntry = &entry;
  }
  if (dynamicEntry == nullptr) {
    fprintf(stderr, "ModLoader: PT_DYNAMIC not found");
    fclose(file);
    return {};
  }
  size_t dynamicDataCount = dynamicEntry->p_filesz / sizeof(Elf64_Dyn);
  Elf64_Dyn dynamicData[dynamicDataCount];
  fseek(file, (long)dynamicEntry->p_offset, SEEK_SET);
  if (fread(dynamicData, sizeof(Elf64_Dyn), dynamicDataCount, file) != dynamicDataCount) {
    perror("ModLoader: PT_DYNAMIC cannot be read");
    fclose(file);
    return {};
  }
  size_t strtabOff  = 0;
  size_t strtabSize = 0;
  for (int i = 0; i < dynamicDataCount; i++) {
    if (dynamicData[i].d_tag == DT_STRTAB) {
      strtabOff = dynamicData[i].d_un.d_val;
    } else if (dynamicData[i].d_tag == DT_STRSZ) {
      strtabSize = dynamicData[i].d_un.d_val;
    }
  }
  if (strtabOff == 0 || strtabSize == 0) {
    fprintf(stderr, "ModLoader: strtab not found");
    fclose(file);
    return {};
  }
  std::vector<char> strtab;
  strtab.resize(strtabSize);
  fseek(file, (long)strtabOff, SEEK_SET);
  if (fread(strtab.data(), 1, strtabSize, file) != strtabSize) {
    perror("ModLoader: strtab cannot be read");
    fclose(file);
    return {};
  }
  std::vector<fs::path> ret;
  for (int i = 0; i < dynamicDataCount; i++) {
    if (dynamicData[i].d_tag == DT_NEEDED) ret.emplace_back(&strtab[dynamicData[i].d_un.d_val]);
  }
  return ret;
}