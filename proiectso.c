#include<stdio.h>
#include<stdlib.h>
#include<dirent.h>
#include<sys/stat.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>
#include<errno.h>
#include<time.h>
#include<sys/wait.h>

int compar;

//verific daca calea data este director
//ne ajuta ca sa decidem cum il procesam ulterior
int isDir(char *path){
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISDIR(path_stat.st_mode);
}

//verific daca directorul este deschis corect, in caz ca nu afisez mesaj de eroare
void checkDir(DIR *directory){
    if(directory==NULL){
        if(errno == ENOENT){
            perror("Directorul nu exista.");
            exit(EXIT_FAILURE);
        }
        if(errno=ENOTDIR){
            perror("Argumentul dat nu este director.");
            exit(EXIT_FAILURE);
        }
        perror("Eroare la deschiderea directorului.");
        exit(EXIT_FAILURE);
    }
}

//functie pentru obtinerea informatiilor directorului pt a le pune in snapshot.
void directory_info(char *dir_path, int snapshot) {
    struct stat dir_stat;
    if (stat(dir_path, &dir_stat) == -1) {
        perror("Eroare la obtinerea informatiilor despre director.");
        exit(EXIT_FAILURE);
    }

    //scriu in snapshot detalii pt fiecare fisier, numele, dimensiunea si ultima modificare
    char buffer[1024];
    int length = snprintf(buffer, sizeof(buffer), "Director: %s\n", dir_path);
    write(snapshot, buffer, length);
    length = snprintf(buffer, sizeof(buffer), "Dimensiune: %ld bytes\n", dir_stat.st_size);
    write(snapshot, buffer, length);
    length = snprintf(buffer, sizeof(buffer), "Ultima modificare: %s", ctime(&dir_stat.st_mtime));
    write(snapshot, buffer, length);
    write(snapshot, "_______________\n", strlen("_______________\n"));
}

//creez snapshot pentru directorul dat dar si pt subdirectoare
void make_snapshot(char *dir_path, int snapshot){
    DIR *directory;
    struct dirent *entry;
    struct stat file_stat;

    directory=opendir(dir_path);
    checkDir(directory);
    
    while((entry=readdir(directory))!=NULL){

        char path[1024];
        if((strcmp(entry->d_name, ".")==0) || (strcmp(entry->d_name, "..")==0)){
            continue;//ignor intrarile de "." si ".."
        }
    
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        if(stat(path, &file_stat)==-1){
            fprintf(stderr, "Eroare la obținerea metadatelor pentru: %s\n", path);
            continue;
        }

        char buffer[1024];
        int length=snprintf(buffer, sizeof(buffer), "Nume: %s\n", entry->d_name);
        write(snapshot, buffer, length);
        length=snprintf(buffer, sizeof(buffer), "Dimensiune: %ld bytes\n", file_stat.st_size);
        write(snapshot, buffer, length);
        length = snprintf(buffer, sizeof(buffer), "Ultima modificare: %s", ctime(&file_stat.st_mtime));
        write(snapshot, buffer, length);
        write(snapshot, "_______________\n", strlen("_______________\n"));


        //verific daca am modificari si in interiorul subdirectoarelor
        if(entry->d_type==DT_DIR && (strcmp(entry->d_name, ".")!=0) && (strcmp(entry->d_name, "..")!=0)){
            char aux[1024];

            snprintf(aux, sizeof(aux), "%s/%s", dir_path, entry->d_name);
            make_snapshot(aux, snapshot);
        }
    }
    closedir(directory);
}

//verific daca am procesat deja directorul dat ca argument
//evit sa procesez de mai multe ori acelasi director
int repetitive(char *dir_path, char **repet_dir, int count_repet){
    for (int i = 0; i < count_repet; i++) {
        if (strcmp(dir_path, repet_dir[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

//verific daca directorul dat ca argument are vreo modificare, comparand directorul cu snapshot-ul corespunzator
void comparDir(char *dir_path, char *snap_path) {
    struct stat dir_stat, snap_stat;
    if (stat(dir_path, &dir_stat) == -1 || stat(snap_path, &snap_stat) == -1) {
        //considerăm că snapshot-ul nu este actual
        compar=1;
        return;
    }

    // Comparam timestamp-urile directorului și ale snapshot-ului
    if (difftime(dir_stat.st_mtime, snap_stat.st_mtime) > 0) {
        //snapshot-ul nu este actual
        compar=1;
        return;
    }

    DIR* directory;
    struct dirent* dir_struct;

    if((directory=opendir(dir_path))==NULL){
      printf("Eroare la deschiderea pentru comparare a directorului %s, se va crea un Snapshot nou!\n",dir_path);
      compar=1;
      return;
    }

    while((dir_struct=readdir(directory))!=NULL){
        if(dir_struct->d_type==DT_DIR && strcmp(dir_struct->d_name,".")!=0 && strcmp(dir_struct->d_name,"..")!=0){
            char path[1024];
            snprintf(path, sizeof(path),"%s/%s", dir_path, dir_struct->d_name);
            comparDir(path, snap_path);
        }
    }
}

//verific daca un fisier nu are toate permisiunile si daca este periculos il izolez
void Permisiuni(char *path, char *isolated_dir){
    DIR *directory;
    struct dirent *dir_struct;
    struct stat file;

    directory=opendir(path);
    checkDir(directory);

    while((dir_struct=readdir(directory))!=NULL){
        if((dir_struct->d_type!=DT_DIR) && (strcmp(dir_struct->d_name, ".")!=0) && (strcmp(dir_struct->d_name,"..")!=0)){
            char aux[1024];
            snprintf(aux, sizeof(aux), "%s/%s", path, dir_struct->d_name);

            if(stat(aux, &file)==-1){
                printf("Eroare deschidere file");
                exit(EXIT_FAILURE);
            }

            if((file.st_mode & S_IRWXU)==0 && (file.st_mode & S_IRWXG)==0 && (file.st_mode & S_IRWXO)==0){
                char command[1024+35];
                snprintf(command, sizeof(command), "./verify_for_malicious.sh %s", aux);

                int out=system(command);
                if(out==-1){
                    exit(EXIT_FAILURE);
                }
                
                int outVal;//ce mi returneaza scriptul

                if(WIFEXITED(out)!=0){
                    outVal=WEXITSTATUS(out);
                }

                //6->periculos 9->safe
                if(outVal==6){
                    char isolated_path[1024];
                    snprintf(isolated_path, sizeof(isolated_path), "%s/%s", isolated_dir, dir_struct->d_name);

                    if(rename(aux, isolated_path)==-1){
                        exit(EXIT_FAILURE);
                    }
                    else{
                        printf("Fisier %s mutat in izolate.\n", aux);
                    }
                }
            
            }
        }
        if(dir_struct->d_type==DT_DIR && strcmp(dir_struct->d_name,".")!=0 && strcmp(dir_struct->d_name,"..")!=0){
            char aux[1024];
            snprintf(aux, sizeof(aux), "%s/%s",path, dir_struct->d_name);

            Permisiuni(aux, isolated_dir);
        }
    }

}


int main(int argc, char *argv[]){
    //verific argumentele sa fie puse in ordine
    if(argc>15 || argc<6){
        printf("Error argc");
        exit(EXIT_FAILURE);
    }

    if(strcmp(argv[1],"-o")!=0 || strcmp(argv[3],"-s")!=0){
        printf("Error argv.");
        exit(EXIT_FAILURE);
    }
    //declar variabile si pun outputul si izolatele in argumentele potrivite
    char *output_dir=argv[2];
    char *isolated_dir=argv[4];
    pid_t copii[10];
    char *repet_dir[10];
    int count_repet=0;
    int count=0;

    // Procesăm fiecare director dat ca argument
    for (int i = 5; i < argc; i++) {
        char *dir_path = argv[i];
        //daca este director si nu s a repetat:
        if (isDir(dir_path) && !repetitive(dir_path, repet_dir, count_repet)) {
            //initial verific daca are toate permisiunile si daca nu, creez procesul intru in script etc.
            Permisiuni(dir_path, isolated_dir);
            //daca trece de functia de permisiuni incep crearea snapshoturilor
            repet_dir[count_repet] = dir_path;
            count_repet++;

            char snapshot_path[1024];
            snprintf(snapshot_path, sizeof(snapshot_path), "%s/snapshot_%d.txt", output_dir, i - 4);
            
            compar=0;
            comparDir(dir_path, snapshot_path);
            if(compar==1){
                pid_t pid=fork();
                if (pid == -1) {
                    perror("Error creating child process");
                    exit(EXIT_FAILURE);
                }
                else if(pid==0){
                    //deschidem fisierul de snapshot pt dir curent
                    int snapshot_fd = open(snapshot_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if(snapshot_fd == -1){
                        perror("Error creating snapshot");
                        exit(EXIT_FAILURE);
                    }

                    directory_info(dir_path, snapshot_fd);
                    // Actualizăm snapshot-ul pentru directorul curent
                    make_snapshot(dir_path, snapshot_fd);
                    // Închidem fișierul de snapshot pentru directorul curent
                    close(snapshot_fd);
                    exit(EXIT_SUCCESS);
                }
                else{
                    copii[count]=pid;
                    count++;
                    printf("Snapshot creat pt directorul %d, %s\n", count, dir_path );
                }
            } 
            else{
                printf("Snapshot-ul pentru directorul '%s' este actual.\n", dir_path);
                }
        }
        else{
            printf("Argumentul '%s' nu este un director sau a fost deja procesat și va fi ignorat.\n", dir_path);
        }
    }
    //astept terminarea tuturor proceselor copil 
    int status;
    for(int i=0;i<count;i++){
        waitpid(copii[i], &status, 0);
        if(WIFEXITED(status)!=0){
            printf("Proces %d cu pid %d, cod %d.\n", i+1, copii[i], WEXITSTATUS(status));
        }
        else{
        printf("Proces cu pid %d s-a terminat cu codul %d cu eroare!\n",copii[i],WEXITSTATUS(status));
        exit(EXIT_FAILURE);
        }
    }
    return 0;
}