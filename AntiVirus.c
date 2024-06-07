#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
// i was helped by github, stackoverflow,google and etc in this code (all the code)
typedef struct virus
{
    unsigned short SigSize;
    char virusName[16];
    unsigned char *sig;
} virus;
typedef struct link link;
struct link
{
    link *nextVirus;
    virus *vir;
};
struct me
{
    char *name;
    char (*fun)(char);
};
void neutralize_virus(char *fileName, int signatureOffset) // got helped the hints and RET site from moodle
{
    FILE *f = fopen(fileName, "rb+");
    if (f == NULL)
    {
        printf("cant open the file\n");
        return;
    }
    fseek(f, signatureOffset, 0);
    char ret = 0xC3;
    char *r = &ret;
    fwrite(r, sizeof(char), 1, f);
    fclose(f);
}

virus *readVirus(FILE *f)
{
    virus *v = malloc(sizeof(virus));
    unsigned short s;
    short a = fread(&s, 2, 1, f);
    if (a != 1)
    {
        free(v);
        return NULL;
    }
    v->SigSize = s;
    v->sig = malloc(v->SigSize);
    if (!v->sig)
    {
        free(v);
        return NULL;
    }
    int b = fread(v->virusName, 16, 1, f);   // virusname, check it
    int c = fread(v->sig, v->SigSize, 1, f); // virus signature
    if (b != 1 || !c)
    {
        free(v->sig);
        free(v);
        return NULL;
    }
    return v;
}

void printVirus(virus *virus, FILE *output, bool check)
{
    if (virus != NULL)
    {
        fprintf(output, "Virus name: %s", virus->virusName);
        fprintf(output, "\n");
        fprintf(output, "Virus size: %d", virus->SigSize);
        fprintf(output, "\n");
        fprintf(output, "signature:\n");
        int a = 0;
        for (int i = 0; i < (int)virus->SigSize; i++)
        {
            a = (a + 1) % 20;
            fprintf(output, "%02x ", virus->sig[i]);
            if (a == 0)
            {
                fprintf(output, "\n");
            }
        }
        fprintf(output, "\n");
        if (!check)
        {
            fprintf(output, "\n");
        }
    }
};
void list_print(link *virus_list, FILE *f)
{
    bool check = false;
    while (virus_list != NULL)
    {
        if (virus_list->nextVirus == NULL)
        {
            check = true;
        }
        printVirus(virus_list->vir, f, check);
        virus_list = virus_list->nextVirus;
    }
}

link *list_append(link *myList, virus *data)
{
    link *new_link = (link *)malloc(sizeof(link));
    new_link->vir = data;
    new_link->nextVirus = NULL;

    if (myList == NULL)
    {
        myList = new_link;
        return new_link; // if the list is empty, return the new link as the head of the list
    }
    else
    {
        link *curr_link = myList;
        while (curr_link->nextVirus != NULL)
        {
            curr_link = curr_link->nextVirus;
        }
        curr_link->nextVirus = new_link;
        return myList; // return the original head of the list
    }
}

void list_free(link *virus_list)
{
    while (virus_list != NULL)
    {
        link *keep = virus_list->nextVirus;
        free(virus_list->vir->sig);
        free(virus_list->vir);
        free(virus_list);
        virus_list = keep;
    }
}
void detect_virus(char *buffer, unsigned int size, link *virus_list, bool fix, char *fileName)
{

    while (virus_list != NULL)
    {
        link *keep = virus_list->nextVirus;
        long int sizeVirus = virus_list->vir->SigSize;
        char *pointer = buffer;
        char *virus = (char *)virus_list->vir->sig;
        for (int i = 0; i < size; i = i + 1)
        {
            if (memcmp(pointer + i, virus, sizeVirus) == 0) // memcmp taken from moodle
            {
                if (!fix)
                {
                    printf("index: 0x%x\n", i);
                    printf("virus name: %s\n", virus_list->vir->virusName);
                    printf("size of sig: %ld\n", sizeVirus);
                    break;
                }
                else
                {
                    neutralize_virus(fileName, i);
                    break;
                }
            }
        }
        virus_list = keep;
    }
}
int detect(link *myList, bool fix, char *fileName)
{
    char buffer[10000];
    fileName[strcspn(fileName, "\n")] = 0; // from tutorialspoint site
    FILE *file = fopen(fileName, "rb");
    if (file == NULL)
    {
        printf("cant open the file\n");
        return 1;
    }
    memset(buffer, 0, sizeof(buffer));
    fread(buffer, 1, 10000, file);
    fseek(file, 0, SEEK_END); // from fresh2refresh site
    long int size = ftell(file);
    if (size > 10000)
    {
        size = 10000;
    }
    detect_virus(buffer, size, myList, fix, fileName);
    fclose(file);
    return 0; // for the return value
}
void quit()
{
}

int main(int argc, char *argv[])
{
    struct me menu2[6]; // from lab1
    menu2[0].name = "Load signatures ";
    menu2[1].name = "Print signatures";
    menu2[2].name = "Detect viruses";
    menu2[3].name = "Fix file";
    menu2[4].name = "quit";
    menu2[5].name = NULL;
    menu2[5].fun = NULL;
    link *myList = NULL;
    char *keep = NULL;
    if (argc > 1)
    {
        keep = argv[1];
    }
    while (1)
    {
        printf("Select operation from the following menu:\n");
        fflush(stdout);
        for (int i = 0; menu2[i].name != NULL; i++)
        {
            printf("%d) : %s\n", i + 1, menu2[i].name);
        }
        printf("answer: ");
        char input[2024];

        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("\n");
            break;
        }
        int choose = atoi(input);
        if (choose > 0 && choose <= 5)
        {
            if (choose == 1)
            {
                char sig[2024];
                printf("write a signature: ");
                fgets(sig, 2024, stdin);
                sig[strcspn(sig, "\n")] = 0;

                FILE *f = fopen(sig, "rb");
                if (!f)
                {
                    printf("cant open the file\n");
                }
                else
                {
                    char magic[5];
                    fread(magic, 4, 1, f);
                    magic[4] = '\0';
                    if (strncmp(magic, "VISL", 4) != 0)
                    {
                        printf("error , not VISL");
                    }
                    else
                    {
                        while (!feof(f))
                        {
                            virus *v = readVirus(f);
                            if (v != NULL)
                            {
                                myList = list_append(myList, v);
                            }
                        }
                        fclose(f);
                    }
                }
            }
            else if (choose == 2)
            {
                list_print(myList, stdout);
            }
            else if (choose == 3)
            {
                if (keep != NULL)
                {
                    detect(myList, false, keep);
                }
                else
                {
                    printf("quit and give a file please");
                }
            }
            else if (choose == 4)
            {
                if (keep != NULL)
                {
                    detect(myList, true, keep);
                }
                else
                {
                    printf("quit and give a file please");
                }
            }
            else if (choose == 5)
            {
                printf("done\n");
                break;
            }
            printf("done\n");
        }
    }
    list_free(myList);
    return 0;
}