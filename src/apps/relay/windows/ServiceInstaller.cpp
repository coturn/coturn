/*!
 * Install service
 * \author Kang Lin <kl222@126.com>
 * \see https://learn.microsoft.com/windows/win32/services/service-configuration-program-tasks
 */

#include "ServiceInstaller.h"
#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <windows.h>

/*!
 * \brief Install service
 *
 * \details Install the current application as a service to the local
 *          service control manager database.
 *
 * \param pszServiceName - the name of the service to be installed
 * \param pszDisplayName - the display name of the service
 * \param dwStartType - the service start option. This parameter can be one of
 *        the following values:
 *          - SERVICE_AUTO_START
 *          - SERVICE_BOOT_START
 *          - SERVICE_DEMAND_START
 *          - SERVICE_DISABLED
 *          - SERVICE_SYSTEM_START.
 * \param pszDependencies - a pointer to a double null-terminated array of null-
 *     separated names of services or load ordering groups that the system
 *     must start before this service.
 * \param pszAccount - the name of the account under which the service runs.
 *        - local account: "NT AUTHORITY\\LocalService"
 *        - network account: "NT AUTHORITY\NetworkService"
 *        - local system account: ".\LocalSystem"
 *        \see https://learn.microsoft.com/windows/win32/services/service-user-accounts
 * \param pszPassword - the password to the account name.
 *
 * \note If the function fails to install the service, it prints the error
 *         in the standard output stream for users to diagnose the problem.
 * \see https://learn.microsoft.com/windows/win32/services/service-configuration-programs
 * \see https://learn.microsoft.com/windows/win32/services/installing-a-service
 */
int InstallService(LPTSTR pszServiceName, LPTSTR pszDisplayName, DWORD dwStartType, LPTSTR pszDependencies,
                   LPTSTR pszAccount, LPTSTR pszPassword) {
  SC_HANDLE schSCManager;
  SC_HANDLE schService;
  TCHAR szUnquotedPath[MAX_PATH];

  if (!GetModuleFileName(NULL, szUnquotedPath, MAX_PATH)) {
    printf("Cannot install service (%lu)\n", GetLastError());
    return -1;
  }

  // In case the path contains a space, it must be quoted so that
  // it is correctly interpreted. For example,
  // "d:\my share\myservice.exe" should be specified as
  // ""d:\my share\myservice.exe"".
  TCHAR szPath[MAX_PATH];
  StringCbPrintf(szPath, MAX_PATH, TEXT("\"%s\""), szUnquotedPath);
  _tprintf(_T("Path: %s\n"), szPath);

  // Open the local default service control manager database
  schSCManager = OpenSCManager(NULL, // local computer
                               NULL, // ServicesActive database
                               SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
  if (NULL == schSCManager) {
    printf("OpenSCManager failed (%lu)\n", GetLastError());
    return -2;
  }

  // Install the service into SCM by calling CreateService
  schService = CreateService(schSCManager,              // SCManager database
                             pszServiceName,            // Name of service
                             pszDisplayName,            // Name to display
                             SERVICE_QUERY_STATUS,      // Desired access
                             SERVICE_WIN32_OWN_PROCESS, // Service type
                             dwStartType,               // Service start type
                             SERVICE_ERROR_NORMAL,      // Error control type
                             szPath,                    // Service's binary
                             NULL,                      // No load ordering group
                             NULL,                      // No tag identifier
                             pszDependencies,           // Dependencies
                             pszAccount,                // Service running account
                             pszPassword                // Password of the account
  );
  if (schService == NULL) {
    printf("CreateService failed (%lu)\n", GetLastError());
    CloseServiceHandle(schSCManager);
    return -3;
  } else
    printf("Service installed successfully\n");

  // Centralized cleanup for all allocated resources.
  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);
  return 0;
}

/*!
 * \brief Uninstall service
 *
 * \details Stop and remove the service from the local service control
 *          manager database.
 *
 * \param pszServiceName - the name of the service to be removed.
 *
 * \note If the function fails to uninstall the service, it prints the
 *   error in the standard output stream for users to diagnose the problem.
 *
 * \see https://learn.microsoft.com/windows/win32/services/deleting-a-service
 */
int UninstallService(LPTSTR pszServiceName) {
  SC_HANDLE schSCManager = NULL;
  SC_HANDLE schService = NULL;
  SERVICE_STATUS ssSvcStatus = {};

  // Open the local default service control manager database
  schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (schSCManager == NULL) {
    printf("OpenSCManager failed (%lu)\n", GetLastError());
    return -1;
  }

  // Open the service with delete, stop, and query status permissions
  schService = OpenService(schSCManager, pszServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
  if (schService == NULL) {
    printf("OpenService failed (%lu)\n", GetLastError());
    CloseServiceHandle(schSCManager);
    return -2;
  }

  // Try to stop the service
  if (ControlService(schService, SERVICE_CONTROL_STOP, &ssSvcStatus)) {
    _tprintf(_T("Stopping %s."), pszServiceName);
    Sleep(1000);

    while (QueryServiceStatus(schService, &ssSvcStatus)) {
      if (ssSvcStatus.dwCurrentState == SERVICE_STOP_PENDING) {
        printf(".");
        Sleep(1000);
      } else
        break;
    }

    if (ssSvcStatus.dwCurrentState == SERVICE_STOPPED) {
      _tprintf(_T("\n%s is stopped.\n"), pszServiceName);
    } else {
      _tprintf(_T("\n%s failed to stop.\n"), pszServiceName);
    }
  }

  // Now remove the service by calling DeleteService.
  if (!DeleteService(schService)) {
    printf("DeleteService failed (%lu)\n", GetLastError());
  } else
    _tprintf(_T("Service deleted %s successfully\n"), pszServiceName);

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);

  return 0;
}
