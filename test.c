int foo(int size, char* data){

    char buf[0x100];

    if (size > 0x100) {
        fprintf(stderr, "size error\n")
        exit(-1)
    }

    memcpy(buf, data, size);
}

int foo2(int size, char* data){
    char buf[0x100];

    for (int i=0; i<size; i++)
       buf[i] = data[i]; 
}