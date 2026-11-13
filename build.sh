cc -O2 -flto -Wall -Wextra -Wpedantic -pthread -o logtopf main.c flow.c packet.c ui.c net_utils.c -lpcap -lncurses
