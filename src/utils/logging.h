#ifndef LOGGING_H
#define LOGGING_H

void log_init(void);
void log_close(void);
void log_write(const char* event, const char* details);

#define LOG(event, details) log_write(event, details)

#endif