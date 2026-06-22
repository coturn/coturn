/*!
 * Install service
 * \author Kang Lin <kl222@126.com>
 *
 * Complete the create and delete of the SC command
 * \see https://learn.microsoft.com/zh-cn/windows/win32/services/configuring-a-service-using-sc#syntax
 */

#ifndef __SERVICEINSTALLER_H_KL_2023_10_20__
#define __SERVICEINSTALLER_H_KL_2023_10_20__

#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief Install service
 *
 * \details Install the current application as a service to the local
 *          service control manager database.
 *
 * \param pszServiceName - the name of the service to be installed
 * \param pszDisplayName - the display name of the service
 * \param dwStartType - the service start option. This parameter can be one of
 *     the following values:
 *       - SERVICE_AUTO_START
 *       - SERVICE_BOOT_START
 *       - SERVICE_DEMAND_START
 *       - SERVICE_DISABLED
 *       - SERVICE_SYSTEM_START.
 * \param pszDependencies - a pointer to a double null-terminated array of null-
 *     separated names of services or load ordering groups that the system
 *     must start before this service.
 * \param pszAccount - the name of the account under which the service runs.
 *       - local account: "NT AUTHORITY\\LocalService"
 *       - network account: "NT AUTHORITY\NetworkService"
 *       - local system account: ".\LocalSystem"
 *       \see https://learn.microsoft.com/windows/win32/services/service-user-accounts
 * \param pszPassword - the password to the account name.
 * \return 0 is success. other is fail
 *
 * \note If the function fails to install the service, it prints the error
 *       in the standard output stream for users to diagnose the problem.
 * \see https://learn.microsoft.com/windows/win32/services/service-configuration-programs
 * \see https://learn.microsoft.com/windows/win32/services/installing-a-service
 */
int InstallService(LPTSTR pszServiceName, LPTSTR pszDisplayName, DWORD dwStartType, LPTSTR pszDependencies,
                   LPTSTR pszAccount, LPTSTR pszPassword);

/*!
 * \brief Uninstall service
 *
 * \details Stop and remove the service from the local service control
 *          manager database.
 *
 * \param pszServiceName - the name of the service to be removed.
 * \return 0 is success. other is fail
 * 
 * \note If the function fails to uninstall the service, it prints the
 *   error in the standard output stream for users to diagnose the problem.
 *
 * \see https://learn.microsoft.com/windows/win32/services/deleting-a-service
 */
int UninstallService(LPTSTR pszServiceName);

#ifdef __cplusplus
}
#endif

#endif //__SERVICEINSTALLER_H_KL_2023_10_20__
