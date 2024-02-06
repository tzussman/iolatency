#ifndef __IOLATENCY_H__
#define __IOLATENCY_H__

#define HIST_SLOTS 17

struct hist {
    __u32 slots[HIST_SLOTS];
};

#endif // __IOLATENCY_H__
