.PHONY: all clean

all: flood v6_flood


######UDP flood and TCP reset flood########
flood: flood.c
	gcc flood.c -o flood
	
######UDP ipv6 flood########	
v6_flood: v6flood.c
	gcc v6flood.c -o v6_flood
		

clean:
	-rm v6_flood flood
