build:
	gcc test/sample.c -o test/sample -static
	gcc test/sample.c -o test/sample_pie -static-pie
	gcc test/dynsample.c -o test/dynsample
	gcc -c skinwalker.c -o skinwalker.o
	gcc main.c skinwalker.o -o skinwalker -static-pie

clean:
	rm -f skinwalker.o skinwalker test/sample test/sample_pie test/dynsample
