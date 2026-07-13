/**
 * @file data_type.h
 * @brief Legacy project-wide fixed data type aliases.
 *
 * New code should prefer <stdbool.h> bool where possible. This header remains
 * available for older modules that use bool_t.
 */
#ifndef DATA_TYPE_H
#define DATA_TYPE_H
#ifdef __cplusplus
extern "C" {
#endif
#include<stdint.h>

/** Legacy boolean type used by older project modules. */
typedef enum {
    /** False value. */
    FALSE = 0,
    /** True value. */
    TRUE = 1
} bool_t;

#ifdef __cplusplus
}
#endif
#endif // DATA_TYPE_H
