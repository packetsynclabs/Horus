#include "kernel.h"

static volatile uint16_t* const VIDEO_MEMORY = (uint16_t*)0xB8000;
static int cursor_x = 0;
static int cursor_y = 0;

#define VGA_COLS 80
#define VGA_ROWS 50   /* 80x50 mode for maximum nerdy boot log density */

static uint8_t current_attr = 0x0F;
static uint8_t last_serial_attr = 0x0F;

static void scroll_screen(void);
static void update_cursor(void);
static void serial_wait(void);

void outb(uint16_t port, uint8_t val) {
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static void update_cursor(void) {
    uint16_t pos = cursor_y * VGA_COLS + cursor_x;
    outb(0x3D4, 14);
    outb(0x3D5, pos >> 8);
    outb(0x3D4, 15);
    outb(0x3D5, pos & 0xFF);
}

/* Classic nerdy VGA trick: reprogram CRTC for 80x50 text mode (8-pixel font height).
 * Gives twice the vertical space for boot logs without switching to graphics mode.
 */
static void vga_set_80x50_text_mode(void) {
    /* Set Maximum Scan Line to 7 (8 lines per character) */
    outb(0x3D4, 0x09);
    outb(0x3D5, 0x07);

    /* Cursor shape for 8-line font */
    outb(0x3D4, 0x0A);
    outb(0x3D5, 0x06);
    outb(0x3D4, 0x0B);
    outb(0x3D5, 0x07);

    /* Vertical Display End for 50 rows (400 scan lines) */
    outb(0x3D4, 0x12);
    outb(0x3D5, 0x8F);   /* 399 lines */

    /* Adjust other registers for 80x50 compatibility */
    outb(0x3D4, 0x14);
    outb(0x3D5, 0x00);
}

// Major: VGA + serial init, basic print/println/hex/decimal with colour + scroll
void terminal_init(void) {
    /* Switch to 80x50 text mode for dense, nerdy boot logs (Knoppix vibes) */
    vga_set_80x50_text_mode();
    clear_screen();
}

static void serial_wait(void) {
    while ((inb(0x3FD) & 0x20) == 0) {}
}

void serial_write_char(char c) {
    serial_wait();
    outb(0x3F8, c);
}

static void serial2_wait(void) {
    while ((inb(0x2FD) & 0x20) == 0) {}
}

void serial2_write_char(char c) {
    serial2_wait();
    outb(0x2F8, c);
}

char serial2_read_char(void) {
    while ((inb(0x2FD) & 1) == 0) {
        yield();
    }
    return inb(0x2F8);
}

static void serial_update_colour(void) {
    if (current_attr == last_serial_attr) return;

    uint8_t fg = current_attr & 0x0F;
    uint8_t bg = (current_attr >> 4) & 0x0F;

    serial_write_char(0x1B);
    serial_write_char('[');
    serial_write_char('0');
    serial_write_char(';');

    if (fg >= 8) {
        serial_write_char('9');
        serial_write_char('0' + (fg - 8));
    } else {
        serial_write_char('3');
        serial_write_char('0' + fg);
    }
    serial_write_char(';');

    serial_write_char('4');
    serial_write_char('0' + (bg & 7));
    serial_write_char('m');

    last_serial_attr = current_attr;
}

void print(const char* str) {
    while (*str) {
        char c = *str;

        /* Hard bounds check to prevent writing outside VGA buffer (was causing hangs
           with very long boot logs in 50-row mode) */
        if (cursor_y >= VGA_ROWS || cursor_x >= VGA_COLS) {
            scroll_screen();
        }

        if (c == '\n') {
            cursor_x = 0;
            cursor_y++;
        } else {
            if (cursor_y < VGA_ROWS && cursor_x < VGA_COLS) {
                VIDEO_MEMORY[cursor_y * VGA_COLS + cursor_x] = (current_attr << 8) | (uint8_t)c;
            }
            cursor_x++;
        }

        if (cursor_x >= VGA_COLS) {
            cursor_x = 0;
            cursor_y++;
        }
        if (cursor_y >= VGA_ROWS) {
            scroll_screen();
        }

        if (c == '\n') {
            serial_write_char('\r');
            serial_write_char('\n');
        } else {
            serial_update_colour();
            serial_write_char(c);
        }

        str++;
    }
    update_cursor();
}

void println(const char* str) { print(str); print("\n"); }

void clear_screen(void) {
    for (int i = 0; i < VGA_COLS * VGA_ROWS; i++) VIDEO_MEMORY[i] = (current_attr << 8) | ' ';
    cursor_x = 0; cursor_y = 0; update_cursor();
}

void print_hex(uint32_t n) {
    char buf[9]; const char* hex = "0123456789ABCDEF";
    for (int i = 7; i >= 0; i--) { buf[i] = hex[n & 0xF]; n >>= 4; }
    buf[8] = '\0';
    print("0x"); print(buf);
}

void print_hex64(uint64_t n) {
    char buf[17]; const char* hex = "0123456789ABCDEF";
    for (int i = 15; i >= 0; i--) { buf[i] = hex[n & 0xF]; n >>= 4; }
    buf[16] = '\0';
    print("0x"); print(buf);
}

void print_char(char c) {
    char s[2] = {c, 0};
    print(s);
}

void set_text_colour(uint8_t attr) {
    current_attr = attr;
}

void print_decimal(uint32_t n) {
    char buf[11];
    int i = 10;
    buf[i] = 0;
    if (n == 0) {
        buf[--i] = '0';
    } else {
        int digits = 0;
        while (n > 0 && digits < 10) {
            buf[--i] = '0' + (n % 10);
            n /= 10;
            digits++;
        }
    }
    print(&buf[i]);
}

static void scroll_screen(void) {
    /* Robust scroll that also resets cursor safely */
    for (int y = 1; y < VGA_ROWS; y++) {
        for (int x = 0; x < VGA_COLS; x++) {
            VIDEO_MEMORY[(y-1) * VGA_COLS + x] = VIDEO_MEMORY[y * VGA_COLS + x];
        }
    }
    for (int x = 0; x < VGA_COLS; x++) {
        VIDEO_MEMORY[(VGA_ROWS-1) * VGA_COLS + x] = (current_attr << 8) | ' ';
    }
    cursor_y = VGA_ROWS - 1;
    cursor_x = 0;
    update_cursor();
}

/* === Boot display aesthetics: make the long nerdy log readable and pretty === */

/* Draw a horizontal rule across the screen in the given colour */
void print_hrule(uint8_t color) {
    uint8_t old = current_attr;
    set_text_colour(color);
    for (int i = 0; i < VGA_COLS; i++) {
        print_char('=');
    }
    println("");
    set_text_colour(old);
}

/* Print N blank lines for vertical breathing room */
void print_blanks(int count) {
    for (int i = 0; i < count; i++) {
        println("");
    }
}

/* Print a prominent section header with underline */
void print_section(const char* title, uint8_t title_color) {
    set_text_colour(title_color);
    print(">> ");
    set_text_colour(0x0F);
    println(title);
    set_text_colour(title_color);
    print("   ");
    for (int i = 0; i < 70; i++) print_char('-');
    println("");
    set_text_colour(0x0F);
}
