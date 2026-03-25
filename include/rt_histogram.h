/**
 * A live histogram display for terminals.
 */

#ifndef RT_HISTOGRAM_H
#define RT_HISTOGRAM_H

#include <curses.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define CINDEX_RED 1
#define CINDEX_CYAN 4

#ifndef X_TICK_SPACING
#define X_TICK_SPACING 10
#endif
#ifndef Y_TICK_SPACING
#define Y_TICK_SPACING 5
#endif

#ifndef countof
#define countof(x) (sizeof(x) / sizeof(*(x)))
#endif

#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

static unsigned int _target_x = 0;
static unsigned int _target_y = 0;
static unsigned int _cutoff_x = 0;

static char histo_xlabel[16] = {0,};
static char histo_ylabel[16] = {0,};

char histogram_title[72] = "Real-time Histogram";
char histogram_title_left[32] = "\0";
char histogram_title_right[32] = "\0";

struct hisogram_axis_mark {
    unsigned int value;
    char label[8];
};

static struct hisogram_axis_mark _x_axis_marks[8] = {0, };
static struct hisogram_axis_mark _y_axis_marks[8] = {0, };

static unsigned int max_u(const unsigned int* buf, unsigned int n) {
    unsigned int max = 0, i;
    for (i = 0; i < n; i++) {
        if (buf[i] > max)
            max = buf[i];
    }
    return max;
}

static void remove_outliers(unsigned int* buf, unsigned int n) {
    unsigned int i;

    for (i = 0; i < n; i++) {
        if (buf[i] >= _cutoff_x)
            buf[i] = 0;
    }
}

static void draw_headline(unsigned int window_width) {
    unsigned int i, x, length;

    attron(A_ITALIC);
    attron(A_BOLD);

    for (i = 0; i < window_width; i++)
        mvaddch(0, i, ' ');

    // Draw left title
    if (histogram_title_left[0]) {
        for (i = 0; i < strlen(histogram_title_left); i++)
            mvaddch(0, i, histogram_title_left[i]);
    }

    // Draw right title
    if (histogram_title_right[0]) {
        length = strlen(histogram_title_right);
        for (i = 0; i < length; i++)
            mvaddch(0, window_width - length - 1 + i, histogram_title_right[i]);
    }

    // Draw center title
    if (histogram_title[0]) {
        length = strlen(histogram_title);
        x = (window_width - length) / 2;
        for (i = 0; i < length; i++)
            mvaddch(0, x + i, histogram_title[i]);
    }

    attroff(A_ITALIC);
    attroff(A_BOLD);
}

static void draw_arrows(unsigned int width, unsigned int height, unsigned int origin_x, unsigned int origin_y) {
    unsigned int i;

    mvaddch(origin_y, origin_x, ACS_LLCORNER);

    // Draw Y-Axis
    for (i = 1 ;; i++) {
        if (i >= height - 1) {
            mvaddch(origin_y - i, origin_x, ACS_UARROW);
            break;
        }

        if (i % Y_TICK_SPACING == 0) {
            mvaddch(origin_y - i, origin_x, ACS_RTEE);
            continue;
        }

        mvaddch(origin_y - i, origin_x, ACS_VLINE);
    }

    // Draw X-Axis
    for (i = 1 ; i < width; i++) {
        if (i >= width - 1) {
            mvaddch(origin_y, origin_x + i, ACS_RARROW);
            break;
        }

        if (i % X_TICK_SPACING == 0) {
            mvaddch(origin_y, origin_x + i, ACS_TTEE);
            continue;
        }

        mvaddch(origin_y, origin_x + i, ACS_HLINE);
    }
}

static void draw_axis_ticks(unsigned int width, unsigned int height, unsigned int origin_x, unsigned int origin_y, unsigned int max_x, unsigned int max_y) {
    unsigned int i, j, slen;
    long x;
    char strbuf[X_TICK_SPACING + 1];

    attron(COLOR_PAIR(CINDEX_CYAN));

    // Draw X ticks
    for (i = X_TICK_SPACING; i < width; i += X_TICK_SPACING) {
        snprintf(strbuf, sizeof(strbuf), "%u", (unsigned int) ((double)max_x * (double)i / (double)width));
        slen = strlen(strbuf);
        x = (long) i - (slen / 2);
        for (j = 0; j < slen; j++)
            mvaddch(origin_y + 1, (long) origin_x + x + (long) j, strbuf[j]);
    }


    // Draw Y ticks
    for (i = Y_TICK_SPACING; i < height; i += Y_TICK_SPACING) {
        snprintf(strbuf, sizeof(strbuf), "%-4u", (unsigned int) ((double)max_y * (double)i / (double)height));
        x = origin_x - 4;
        for (j = 0; j < 4; j++)
            mvaddch(origin_y - i, x + j, strbuf[j]);
    }

    attroff(COLOR_PAIR(CINDEX_CYAN));
}

static void draw_axis_labels(unsigned int origin_x, unsigned int origin_y, unsigned int width, unsigned int height) {
    unsigned int i;

    attron(COLOR_PAIR(CINDEX_CYAN));
    attron(A_ITALIC);

    // x label
    for (i = 0; i < strlen(histo_xlabel); i++)
        mvaddch(origin_y - 1, origin_x + width - i - 2, histo_xlabel[strlen(histo_xlabel) - i - 1]);

    // y label
    for (i = 0; i < strlen(histo_ylabel); i++)
        mvaddch(origin_y - height + 2, origin_x + i + 2, histo_ylabel[i]);

    attroff(A_ITALIC);
    attroff(COLOR_PAIR(CINDEX_CYAN));
}

static void draw_axis_marks(unsigned int origin_x, unsigned int origin_y, unsigned int max_x, unsigned int max_y, unsigned int width, unsigned int height) {
    unsigned int i, j, x;

    attron(COLOR_PAIR(CINDEX_RED));

    for (i = 0; i < countof(_x_axis_marks); i++) {
        if (!_x_axis_marks[i].value)
            break;

        x = (unsigned int) round((double) width * (double)_x_axis_marks[i].value / (double)max_x);

        if (x + 1 + strlen(_x_axis_marks[i].label) > width)
            continue;

        mvaddch(origin_y, origin_x + x, ACS_DIAMOND);

        for (j = 0; j < strlen(_x_axis_marks[i].label); j++)
            mvaddch(origin_y, origin_x + x + j + 1, _x_axis_marks[i].label[j]);
    }

    for (i = 0; i < countof(_y_axis_marks); i++) {
        if (!_y_axis_marks[i].value)
            break;

        x = (unsigned int) round((double) height * (double)_y_axis_marks[i].value / (double)max_y);

        if (x + 1 + strlen(_y_axis_marks[i].label) > height)
            continue;

        mvaddch(origin_y - x, origin_x, ACS_DIAMOND);

        for (j = 0; j < strlen(_y_axis_marks[i].label); j++)
            mvaddch(origin_y - x + j + 1, origin_x, _y_axis_marks[i].label[j]);
    }

    attroff(COLOR_PAIR(CINDEX_RED));
}

static void draw_axes(unsigned int width, unsigned int height, unsigned int origin_x, unsigned int origin_y, unsigned int max_x, unsigned int max_y) {
    draw_arrows(width, height, origin_x, origin_y);
    draw_axis_ticks(width, height, origin_x, origin_y, max_x, max_y);
    draw_axis_labels(origin_x, origin_y, width, height);
    draw_axis_marks(origin_x, origin_y, max_x, max_y, width, height);
}

static void draw_bucket(unsigned int bucket, unsigned int value, unsigned int origin_x, unsigned int origin_y, unsigned int height, unsigned int max_y) {
    unsigned int i;

    for (i = 0; i < round((height - 1) * ((double)value / (double) max_y)); i++)
        mvaddch(origin_y - i - 1, origin_x + bucket, ACS_CKBOARD);
}

static void draw_histogram_buckets(const unsigned int* buckets, unsigned int origin_x, unsigned int origin_y, unsigned int width, unsigned int height, unsigned int max_y) {
    unsigned int i;

    for (i = 0; i < width; i++)
        draw_bucket(i, buckets[i], origin_x, origin_y, height, max_y);
}


static unsigned int lfsr16(unsigned char reset) {
    static unsigned int lfsr = 0xACE1u;
    unsigned int lsb;

    if (reset)
        lfsr = 0xACE1u;

    lsb = lfsr & 1;

    lfsr >>= 1;
    if (lsb)
        lfsr ^= 0xB400u;

    return lfsr;
}

static unsigned int get_bucket(unsigned int value, unsigned int width, unsigned int max_x) {
    double x = (double) value * (double)width / (double)max_x;
    double split_ratio = x - floor(x);
    unsigned char offset = (lfsr16(0) & 0xffff) < (split_ratio * (double) 0xffff) ? 1 : 0;

    return (unsigned int) floor(x) + offset;
}

// Returns max_y
static unsigned int do_draw_histogram(const unsigned int* values, unsigned long num_values, unsigned int origin_x, unsigned int origin_y, unsigned int width, unsigned int height, unsigned int max_x) {
    unsigned int i, bucket_index;
    unsigned int* buckets = calloc(width, sizeof(*buckets));
    unsigned int max_y;

    for (i = 0; i < num_values; i++) {
        /*if (values[i] == 0)
            continue;*/
        bucket_index = get_bucket(values[i], width, max_x);
        if (bucket_index >= width)
            continue;
        buckets[bucket_index]++;
    }

    max_y = max(max_u(buckets, width), _target_y);
    draw_histogram_buckets(buckets, origin_x, origin_y, width, height, max_y);
    free(buckets);

    return max_y;
}

static void clear_histogram(unsigned int origin_x, unsigned int origin_y, unsigned int width, unsigned int height) {
    unsigned int i, j;

    for (i = 1; i < width; i++) {
        for (j = 1; j < height; j++) {
            mvaddch(origin_y - j, origin_x + i, ' ');
        }
    }
}

/**
 * Initializes the histogram with given dimensions.
 *
 * @param target_x: The expected maximum of values on the x axis. The maximum value of the x axis will not decrease below this threshold, but may dynamically increase.
 * @param target_y: The expected maximum of values on the y axis. The maximum value of the y axis will not decrease below this threshold, but may dynamically increase.
 * @param cutoff_x: Values above this threshold will not be displayed. If set to the same value as `target_x`, the maximum of the x axis is fixed.
 */
static void histogram_init(unsigned int target_x, unsigned int target_y, unsigned int cutoff_x) {
    initscr();
    noecho();
    nonl();
    cbreak();
    curs_set(FALSE);
    keypad(stdscr, TRUE);
    if (!has_colors())
        return;

    start_color();
    // Misc colors
    init_pair(CINDEX_RED, COLOR_RED,     COLOR_BLACK);
    init_pair(2, COLOR_YELLOW,  COLOR_BLACK);
    init_pair(3, COLOR_GREEN,   COLOR_BLACK);
    init_pair(CINDEX_CYAN, COLOR_CYAN,    COLOR_BLACK);
    init_pair(5, COLOR_MAGENTA, COLOR_BLACK);

    // Axes and bars
    init_pair(6, COLOR_WHITE,   COLOR_BLACK);
    init_pair(7, COLOR_BLUE,    COLOR_BLACK);

    _target_x = target_x;
    _target_y = target_y;
    _cutoff_x = cutoff_x;
}

/**
 * Add a red mark to the x axis.
 *
 * @param value The value that the mark corresponds to.
 * @param label The mark's label.
 * @return A pointer to a hisogram_axis_mark struct instance. Update this instance to change the label's properties at a later time.
 */
static struct hisogram_axis_mark* histogram_add_x_axis_mark(unsigned int value, char* label) {
    unsigned int i;

    for (i = 0; i < countof(_x_axis_marks); i++) {
        if (!_x_axis_marks[i].value) {
            _x_axis_marks[i].value = value;
            strncpy(_x_axis_marks[i].label, label, sizeof(_x_axis_marks[i].label));
            _x_axis_marks[i].label[sizeof(_x_axis_marks[i].label) - 1] = '\0';
            return &_x_axis_marks[i];
        }
    }

    return NULL;
}

/**
 * Add a red mark to the y axis.
 *
 * @param value The value that the mark corresponds to.
 * @param label The mark's label.
 * @return A pointer to a hisogram_axis_mark struct instance. Update this instance to change the label's properties at a later time.
 */
static struct hisogram_axis_mark* histogram_add_y_axis_mark(unsigned int value, char* label) {
    unsigned int i;

    for (i = 0; i < countof(_y_axis_marks); i++) {
        if (!_y_axis_marks[i].value) {
            _y_axis_marks[i].value = value;
            strncpy(_y_axis_marks[i].label, label, sizeof(_y_axis_marks[i].label));
            _y_axis_marks[i].label[sizeof(_y_axis_marks[i].label) - 1] = '\0';
            return &_y_axis_marks[i];
        }
    }

    return NULL;
}

/**
 * Updates the histogram such that it displays the number of times each values in `values` occurs.
 *
 * @param values: An array of values. The histogram will display the number of occurences for each value in `values`.
 * @param num_values: The amount of values in `values`.
 */
static void histogram_update(unsigned int* values, unsigned long num_values) {
    static unsigned int lastheight = 0, lastwidth = 0;
    unsigned int height, width;
    unsigned int hist_width, hist_height, origin_x, origin_y, max_x, max_y;

    lfsr16(1);

    getmaxyx(stdscr, height, width);
    if (lastheight != height || lastwidth != width)
        clear();
    lastheight = height;
    lastwidth = width;

    hist_width = width - 7;
    hist_height = height - 3;
    origin_x = 5;
    origin_y = height - 2;

    remove_outliers(values, num_values);
    max_x = max_u(values, num_values);
    max_x = max(max_x, _target_x);

    clear_histogram(origin_x, origin_y, hist_width, hist_height);
    max_y = do_draw_histogram(values, num_values, origin_x, origin_y, hist_width, hist_height, max_x);
    draw_axes(hist_width, hist_height, origin_x, origin_y, max_x, max_y);
    draw_headline(width);

    refresh();
}

#endif