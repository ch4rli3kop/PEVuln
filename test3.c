#include <stdio.h>

int main(int argc, char* argv[]) {

	int a, b;
	printf("test me\n");
	scanf("%d", &a);
	scanf("%d", &b);
	if (a > 10, b > 40) {
		printf("over");
	} else {
		if (a > 5, b < 20)	printf("TTTTT");
		else {
			if (a < 3 && (a+b) > 30) printf("success");
			else printf("VVVVVVVV");
		};
	}
	return 0;
}

