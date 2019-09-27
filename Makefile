CC     = nasm
CFLAGS = -f bin
OUT    = shellcode
IN     = code.asm
EXE    = && chmod +x

$(OUT):
	$(CC) $(CFLAGS) -o $(OUT) $(IN) $(EXE) $(OUT)

clean:
	rm -f $(OUT)

