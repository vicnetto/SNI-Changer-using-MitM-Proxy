#include "configuration.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int read_config_file(struct sni_change **sni_changes) {

    // Open the configuration file.
    FILE *config_file = fopen(CONFIGURATION_FILE_NAME, "r");
    if (config_file == NULL) {
        fprintf(stderr, "(error) Missing configuration file: %s.\n",
                CONFIGURATION_FILE_NAME);
        return -1;
    }

    // Count valid lines in the file.
    int valid_lines = 0;
    char line[2 * (DOMAIN_MAX_SIZE + 1)];
    while (fgets(line, sizeof(line), config_file)) {
        if (line[0] != '#' && line[0] != '\n') {
            valid_lines++;
        }
    }

    if (valid_lines == 0) {
        fprintf(stdout,
                "(info) No sni change specified in the configuration file.\n");
        fclose(config_file);
        return -1;
    }

    *sni_changes = (struct sni_change *)malloc((valid_lines + 1) *
                                               sizeof(struct sni_change));

    if (*sni_changes == NULL) {
        fprintf(
            stderr,
            "(error) Impossible to allocate space for configuration data.\n");
        goto error;
    }

    // Return to the beginning of the file.
    fseek(config_file, 0, SEEK_SET);

    int current_line = 0;
    while (fgets(line, sizeof(line), config_file)) {
        // Ignore comment lines.
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        // Extract domain and sni and save to the struct.
        char *rest = line;
        const char *domain = strtok_r(rest, ";", &rest);
        char *sni = strtok_r(rest, ";", &rest);

        if (domain == NULL || sni == NULL) {
            fprintf(stderr, "(error) Invalid configuration file.\n");
            goto error;
        }

        if (sni[strlen(sni) - 1] == '\n')
            sni[strlen(sni) - 1] = '\0';

        strncpy((*sni_changes)[current_line].domain, domain, DOMAIN_MAX_SIZE);
        strncpy((*sni_changes)[current_line].sni, sni, DOMAIN_MAX_SIZE);
        current_line++;
    }

    strncpy((*sni_changes)[current_line].domain, "\0", DOMAIN_MAX_SIZE);
    strncpy((*sni_changes)[current_line].sni, "\0", DOMAIN_MAX_SIZE);

    // Fechar o arquivo de configuração
    fclose(config_file);

    // Exemplo de como usar os dados da struct
    for (int i = 0; i < valid_lines; i++) {
        fprintf(stdout, "(config) Domain: %s, SNI: %s\n",
                (*sni_changes)[i].domain, (*sni_changes)[i].sni);
    }

    return 0;
error:
    fclose(config_file);
    exit(0);
}
