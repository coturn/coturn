/*!
 * Service
 * \author Kang Lin <kl222@126.com>
 */

#ifndef __SERVICE_H_KL_2023_10_20__
#define __SERVICE_H_KL_2023_10_20__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*! Perform service-specific initialization.
 * \param arg: the number of the command-line arguments passed in from the SCM(service control manager)
 * \param argv: the array of the command-line arguments passed in from the SCM(service control manager)
 * \return
 *   - 0: success
 *   - other: error code
 */
typedef long (*fnServiceStart)(int arg, char *argv[]);

/*!Perform service work. Block until stopped.
 * \return
 *   - 0: success
 *   - other: error code
 */
typedef long (*fnServiceRun)();

/*!
 * Stop service. The function should return as quickly as possible;
 * if it does not return within 30 seconds, the SCM returns an error.
 * \see https://learn.microsoft.com/windows/win32/api/winsvc/nc-winsvc-lphandler_function
 */
typedef void (*fnServiceStop)();

/*!
 * Run service
 * \param name: the name of service
 * \param start: the callback function of start. it maybe NULL
 * \param run: the callback function of run. it maybe NULL
 * \param stop: the callback function of stop. it maybe NULL
 */
int ServiceRun(char *name, fnServiceStart start, fnServiceRun run, fnServiceStop stop);

/*!
 * log function
 */
typedef void (*fnServiceLog)(char *msg);

/*!
 * Set service log
 * \param log: the callback function of log. it maybe NULL
 * \return the old log function
 */
fnServiceLog SetServiceLog(fnServiceLog log);

/*!
 * Get log function
 */
fnServiceLog GetServiceLog();

void SetLogFile(const char *pFile);

#ifdef __cplusplus
}
#endif

#endif //__SERVICE_H_KL_2023_10_20__
