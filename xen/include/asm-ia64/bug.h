#ifndef __IA64_BUG_H__
#define __IA64_BUG_H__

#define BUG() __bug(__FILE__, __LINE__)
#define WARN() __warn(__FILE__, __LINE__)

#endif /* __IA64_BUG_H__ */
