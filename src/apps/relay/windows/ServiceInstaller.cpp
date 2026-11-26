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
#include <AtlBase.h>
#include <AtlConv.h>
#include <string>

std::string ErrorString(DWORD nErr = GetLastError()) {
  USES_CONVERSION;
  std::string msg;
  LPVOID lpMsgBuf;
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      nErr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
      (LPTSTR)&lpMsgBuf, 0, NULL);
  if (lpMsgBuf) {
    msg = CT2A((LPCTSTR)lpMsgBuf);
  }
  LocalFree(lpMsgBuf);
  return msg;
}

int InstallService(LPTSTR pszServiceName, LPTSTR pszDisplayName, DWORD dwStartType, LPTSTR pszDependencies,
                   LPTSTR pszAccount, LPTSTR pszPassword) {
  SC_HANDLE schSCManager;
  SC_HANDLE schService;
  TCHAR szUnquotedPath[MAX_PATH];

  if (!GetModuleFileName(NULL, szUnquotedPath, MAX_PATH)) {
    printf("Cannot install service: [%d] %s\n", GetLastError(), ErrorString().c_str());
    return GetLastError();
  }

  // In case the path contains a space, it must be quoted so that
  // it is correctly interpreted. For example,
  // "d:\my share\myservice.exe" should be specified as
  // ""d:\my share\myservice.exe"".
  TCHAR szPath[MAX_PATH];
  StringCbPrintf(szPath, MAX_PATH, TEXT("\"%s\""), szUnquotedPath);
  printf(_T("Path: %s\n"), szPath);

  // Open the local default service control manager database
  schSCManager = OpenSCManager(NULL, // local computer
                               NULL, // ServicesActive database
                               SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
  if (NULL == schSCManager) {
    printf("OpenSCManager failed: [%d] %s\n", GetLastError(), ErrorString().c_str());
    return GetLastError();
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
    printf("CreateService failed: [%d] %s\n", GetLastError(), ErrorString().c_str());
    CloseServiceHandle(schSCManager);
    return GetLastError();
  } else
    printf("Service installed successfully\n");

  // Centralized cleanup for all allocated resources.
  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);
  return 0;
}

int UninstallService(LPTSTR pszServiceName) {
  SC_HANDLE schSCManager = NULL;
  SC_HANDLE schService = NULL;
  SERVICE_STATUS ssSvcStatus = {};

  // Open the local default service control manager database
  schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (schSCManager == NULL) {
    printf("OpenSCManager failed: [%d] %s\n", GetLastError(), ErrorString().c_str());
    return GetLastError();
  }

  // Open the service with delete, stop, and query status permissions
  schService = OpenService(schSCManager, pszServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
  if (schService == NULL) {
    printf("OpenService failed: [%d] %s\n", GetLastError(), ErrorString().c_str());
    CloseServiceHandle(schSCManager);
    return GetLastError();
  }

  // Try to stop the service
  if (ControlService(schService, SERVICE_CONTROL_STOP, &ssSvcStatus)) {
    printf(_T("Stopping %s."), pszServiceName);
    int nCount = 100;
    while (QueryServiceStatus(schService, &ssSvcStatus) && nCount-- > 0) {
      if (ssSvcStatus.dwCurrentState == SERVICE_STOP_PENDING) {
        printf(".");
        Sleep(100);
      } else
        break;
    }

    if (ssSvcStatus.dwCurrentState == SERVICE_STOPPED) {
      printf(_T("\n%s is stopped.\n"), pszServiceName);
    } else {
      printf(_T("\n%s failed to stop. state: 0x%X\n"), pszServiceName, ssSvcStatus.dwCurrentState);
    }
  }

  // Now remove the service by calling DeleteService.
  if (!DeleteService(schService)) {
    printf("DeleteService failed: [%d] %s\n", GetLastError(), ErrorString().c_str());
  } else {
    printf(_T("Service deleted %s successfully\n"), pszServiceName);
  }
  
  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);

  return 0;
}
