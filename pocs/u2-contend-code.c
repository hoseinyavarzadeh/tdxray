#include "ttoolbox.h"
#include <termios.h>

// Set terminal to non-blocking input mode
static void set_input_nb() {
    static struct termios oldt, newt;

    tcgetattr(STDIN_FILENO, &oldt); // Save current settings
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO); // Disable canonical mode and echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
}

// Check if Enter has been pressed
static unsigned char enter_pressed() {
    struct timeval tv = {0, };
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) <= 0)
        return 0;

    return getchar() == '\n';
}

const char* get_mode_label(unsigned char mode) {
    switch (mode) {
        case 0:
            return CRED "OFF" CRESET;
        case 1:
            return CCYN "DATA READ" CRESET;
        case 2:
            return CCYN "DATA WRITE" CRESET;
        default:;
    }
    return CMAG "CODE" CRESET;
}

int main() {
    unsigned char state_on = 1, load_index = 0;
    unsigned char* target_page;
    volatile unsigned char* comm_page;
    volatile struct {
        unsigned long target_addr;
        unsigned char on;
    }* target_info;
    const char loading[] = "-\\|/";
    unsigned long scratchboard;

    if (getuid() != 0) {
        printf("I need root privileges\n");
        exit(EXIT_FAILURE);
    }

    // Map a shared page to communicate with the child process
    comm_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
    if (!comm_page || comm_page == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    target_info = (volatile void*) comm_page;

    // Map the target page
    target_page = mmap((void*)0x4200000000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_SHARED | MAP_POPULATE, -1, 0);
    if (!target_page || target_page == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // Fill target page with RET so that we can call it
    *target_page = 0xc3;

    target_info->target_addr = (unsigned long) target_page;
    target_info->on = state_on;

    // Spawn child that does the actual cache line accesses for us
    if (!fork()) {
        die_with_parent();
        for (int c = 0;;) {
            switch (target_info->on) {
                case 0:
                    break;
                case 1:
                    asm volatile ("mov (%0), %1" :: "r"(target_info->target_addr), "r"(0));
                    break;
                case 2:
                    asm volatile ("mov %1, 8(%0)" :: "r"(target_info->target_addr), "r"(c++));
                    break;
                default:
                    asm volatile("call *%0" :: "r"(target_page), "a"(scratchboard));
                    break;
            }
        }
    }

    // Nice interface to see what is going on
    set_input_nb();
    printf("Looping " CCYN "'%s'" CRESET "\n",  "mov (%0), %1");
    printf("%%0 has GPA " CGRN "0x%lx" CRESET " ...\n", virt_to_phys(target_page) & ~0xffful);
    printf("Press enter to toggle between data accesses, code accesses, and no accesses\n");
    for (;;) {
        printf("\r[%c] State: %s" CRESET "      ", loading[load_index++ % strlen(loading)], get_mode_label(state_on));
        fflush(stdout);

        if (enter_pressed()) {
            state_on = (state_on + 1) % 4;
            target_info->on = state_on;
        }
        usleep(100000);
    }
}
